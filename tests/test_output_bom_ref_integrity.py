# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


import copy
from datetime import datetime, timezone
from json import loads as json_loads
from unittest import TestCase
from uuid import UUID

from cyclonedx.exception.model import DuplicateBomRefException, UnknownComponentDependencyException
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.definition import Standard
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.tool import ToolRepository
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator

SV = SchemaVersion.V1_6
FIXED_SERIAL = UUID('12345678-1234-5678-1234-567812345678')
FIXED_TS = datetime(2024, 1, 1, tzinfo=timezone.utc)


def _bom_without_refs() -> Bom:
    bom = Bom(components=[Component(name='anon', type=ComponentType.LIBRARY)])
    bom.serial_number = FIXED_SERIAL
    bom.metadata.timestamp = FIXED_TS
    return bom


def _bom_with_duplicate_refs() -> Bom:
    shared = 'shared-ref'
    component = Component(name='comp', type=ComponentType.LIBRARY, bom_ref=shared)
    tool_component = Component(name='tool', type=ComponentType.LIBRARY, bom_ref=shared)
    standard = Standard(bom_ref=shared, name='STD')
    bom = Bom(components=[component])
    bom.serial_number = FIXED_SERIAL
    bom.metadata = BomMetaData(tools=ToolRepository(components=[tool_component]))
    bom.metadata.timestamp = FIXED_TS
    bom._definitions.standards.add(standard)
    return bom


class TestReproducibleOutput(TestCase):

    def test_missing_ref_is_stable_across_exports(self) -> None:
        refs = {}
        for _ in range(3):
            doc = json_loads(make_outputter(_bom_without_refs(), OutputFormat.JSON, SV)
                             .output_as_string())
            refs.setdefault('json', set()).add(doc['components'][0]['bom-ref'])
        self.assertEqual(1, len(refs['json']))
        self.assertEqual('BomRef.1', next(iter(refs['json'])))

    def test_missing_ref_matches_between_json_and_xml(self) -> None:
        bom = _bom_without_refs()
        json_ref = json_loads(
            make_outputter(bom, OutputFormat.JSON, SV).output_as_string()
        )['components'][0]['bom-ref']
        xml = make_outputter(bom, OutputFormat.XML, SV).output_as_string()
        self.assertIn(f'bom-ref="{json_ref}"', xml)

    def test_output_is_byte_reproducible(self) -> None:
        first = make_outputter(_bom_without_refs(), OutputFormat.JSON, SV).output_as_string()
        second = make_outputter(_bom_without_refs(), OutputFormat.JSON, SV).output_as_string()
        self.assertEqual(first, second)
        first_xml = make_outputter(_bom_without_refs(), OutputFormat.XML, SV).output_as_string()
        second_xml = make_outputter(_bom_without_refs(), OutputFormat.XML, SV).output_as_string()
        self.assertEqual(first_xml, second_xml)

    def test_explicit_refs_are_emitted_verbatim(self) -> None:
        bom = Bom(components=[
            Component(name='named', type=ComponentType.LIBRARY, bom_ref='my-explicit-ref')])
        bom.serial_number = FIXED_SERIAL
        doc = json_loads(make_outputter(bom, OutputFormat.JSON, SV).output_as_string())
        self.assertEqual('my-explicit-ref', doc['components'][0]['bom-ref'])
        xml = make_outputter(bom, OutputFormat.XML, SV).output_as_string()
        self.assertIn('bom-ref="my-explicit-ref"', xml)


class TestDuplicateBomRefRejected(TestCase):

    def test_duplicate_ref_raises_in_both_formats(self) -> None:
        for output_format in (OutputFormat.JSON, OutputFormat.XML):
            bom = _bom_with_duplicate_refs()
            with self.assertRaises(DuplicateBomRefException) as error:
                make_outputter(bom, output_format, SV).output_as_string()
            self.assertIn('shared-ref', str(error.exception))

    def test_duplicate_ref_failure_leaves_caller_bom_untouched(self) -> None:
        bom = _bom_with_duplicate_refs()
        snapshot = copy.deepcopy(bom)
        with self.assertRaises(DuplicateBomRefException):
            make_outputter(bom, OutputFormat.JSON, SV).output_as_string()
        self.assertEqual(snapshot, bom)
        self.assertEqual(
            ['shared-ref'], [c.bom_ref.value for c in bom.components])
        self.assertEqual(
            ['shared-ref'], [s.bom_ref.value for s in bom._definitions.standards])
        self.assertEqual(
            ['shared-ref'], [c.bom_ref.value for c in bom.metadata.tools.components])


class TestCallerBomNotMutated(TestCase):

    def test_successful_export_does_not_mutate_bom(self) -> None:
        bom = _bom_without_refs()
        snapshot = copy.deepcopy(bom)
        make_outputter(bom, OutputFormat.JSON, SV).output_as_string()
        make_outputter(bom, OutputFormat.XML, SV).output_as_string()
        self.assertEqual(snapshot, bom)
        self.assertIsNone(bom.components[0].bom_ref.value)

    def test_failed_export_does_not_add_dependency_entries(self) -> None:
        bom = _bom_without_refs()
        bom.dependencies.add(Dependency(BomRef('unknown-ref')))
        before = len(bom.dependencies)
        for output_format in (OutputFormat.JSON, OutputFormat.XML):
            with self.assertRaises(UnknownComponentDependencyException):
                make_outputter(bom, output_format, SV).output_as_string()
        self.assertEqual(before, len(bom.dependencies))


class TestGeneratedDocumentsAreSchemaValid(TestCase):

    def test_outputs_validate_against_schemas(self) -> None:
        for output_format in (OutputFormat.JSON, OutputFormat.XML):
            doc = make_outputter(_bom_without_refs(), output_format, SV).output_as_string()
            error = make_schemabased_validator(output_format, SV).validate_str(doc)
            self.assertIsNone(error, f'{output_format.name}: {error}')

    def test_standard_with_ref_validates_in_both_formats(self) -> None:
        bom = Bom(components=[
            Component(name='comp', type=ComponentType.LIBRARY, bom_ref='comp-ref')])
        bom.serial_number = FIXED_SERIAL
        bom._definitions.standards.add(
            Standard(bom_ref='std-ref', name='STD', version='1.0',
                     description='a standard', owner='acme'))
        for output_format in (OutputFormat.JSON, OutputFormat.XML):
            doc = make_outputter(bom, output_format, SV).output_as_string()
            error = make_schemabased_validator(output_format, SV).validate_str(doc)
            self.assertIsNone(error, f'{output_format.name}: {error}')
