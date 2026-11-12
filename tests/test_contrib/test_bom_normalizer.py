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


from unittest import TestCase

from cyclonedx.contrib.bom.utils import BomRefDiscriminator, BomRefNormalizer, iter_all_identity_bom_refs
from cyclonedx.exception.model import DuplicateBomRefException
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.definition import Standard
from cyclonedx.model.license import DisjunctiveLicense
from cyclonedx.model.service import Service
from cyclonedx.model.tool import ToolRepository


class TestBomRefNormalizer(TestCase):

    def test_fills_missing_primary_refs_deterministically(self) -> None:
        refs = [BomRef('explicit'), BomRef(), BomRef()]
        normalizer = BomRefNormalizer(refs)
        normalizer.discriminate()
        self.assertEqual('explicit', refs[0].value)
        self.assertEqual('BomRef.1', refs[1].value)
        self.assertEqual('BomRef.2', refs[2].value)
        # a second run on fresh objects produces the exact same values
        again = [BomRef('explicit'), BomRef(), BomRef()]
        BomRefNormalizer(again).discriminate()
        self.assertEqual([r.value for r in refs], [r.value for r in again])
        normalizer.reset()
        self.assertEqual(['explicit', None, None], [r.value for r in refs])

    def test_explicit_values_are_never_renamed(self) -> None:
        refs = [BomRef('a'), BomRef('b')]
        with BomRefNormalizer(refs):
            self.assertEqual(['a', 'b'], [r.value for r in refs])
        self.assertEqual(['a', 'b'], [r.value for r in refs])

    def test_duplicate_explicit_value_raises_and_names_ref(self) -> None:
        refs = [BomRef('dup'), BomRef('dup')]
        with self.assertRaises(DuplicateBomRefException) as error:
            BomRefNormalizer(refs).discriminate()
        self.assertIn('dup', str(error.exception))
        # nothing was renamed when the conflict was detected
        self.assertEqual(['dup', 'dup'], [r.value for r in refs])

    def test_shared_bomref_instance_is_not_a_conflict(self) -> None:
        shared = BomRef('shared')
        refs = [shared, shared, BomRef()]
        with BomRefNormalizer(refs):
            self.assertEqual('shared', shared.value)
            self.assertEqual('BomRef.1', refs[2].value)

    def test_shared_missing_bomref_instance_gets_one_value(self) -> None:
        shared = BomRef()
        refs = [shared, shared]
        with BomRefNormalizer(refs):
            self.assertEqual('BomRef.1', shared.value)

    def test_nested_missing_refs_are_left_alone(self) -> None:
        primary = [BomRef()]
        nested = [BomRef(), BomRef('nested-explicit')]
        with BomRefNormalizer(primary, nested):
            self.assertEqual('BomRef.1', primary[0].value)
            self.assertIsNone(nested[0].value)
            self.assertEqual('nested-explicit', nested[1].value)

    def test_nested_duplicate_value_raises(self) -> None:
        primary = [BomRef('primary')]
        nested = [BomRef('same'), BomRef('same')]
        with self.assertRaises(DuplicateBomRefException):
            BomRefNormalizer(primary, nested).discriminate()

    def test_context_manager_resets_on_exception(self) -> None:
        refs = [BomRef('dup'), BomRef('dup'), BomRef()]
        original = [r.value for r in refs]
        with self.assertRaises(DuplicateBomRefException):
            with BomRefNormalizer(refs):
                pass
        self.assertEqual(original, [r.value for r in refs])

    def test_generated_value_avoids_explicit_collision(self) -> None:
        normalizer = BomRefNormalizer([BomRef()])
        # an explicit value already occupies the first generated slot
        new_value = normalizer._make_missing_value(1, {'BomRef.1': BomRef('BomRef.1')})
        self.assertEqual('BomRef.2', new_value)


class TestBomRefNormalizerFromBom(TestCase):

    def test_covers_components_services_tools_and_definitions(self) -> None:
        component = Component(name='comp', type=ComponentType.LIBRARY)
        nested = Component(name='nested', type=ComponentType.LIBRARY)
        component.components.add(nested)
        tool_component = Component(name='tool', type=ComponentType.LIBRARY)
        service = Service(name='serv')
        standard = Standard(name='STD')
        bom = Bom(components=[component], services=[service])
        bom.metadata = BomMetaData(tools=ToolRepository(components=[tool_component]))
        bom._definitions.standards.add(standard)
        with BomRefNormalizer.from_bom(bom):
            refs = {
                component.bom_ref.value, nested.bom_ref.value,
                tool_component.bom_ref.value, service.bom_ref.value,
                standard.bom_ref.value,
            }
            self.assertEqual(5, len(refs))
            self.assertEqual(
                {'BomRef.1', 'BomRef.2', 'BomRef.3', 'BomRef.4', 'BomRef.5'}, refs)
        # everything restored after the context
        self.assertIsNone(component.bom_ref.value)
        self.assertIsNone(nested.bom_ref.value)
        self.assertIsNone(tool_component.bom_ref.value)
        self.assertIsNone(service.bom_ref.value)
        self.assertIsNone(standard.bom_ref.value)

    def test_conflict_between_component_tool_and_standard_raises(self) -> None:
        component = Component(name='comp', type=ComponentType.LIBRARY, bom_ref='shared')
        tool_component = Component(name='tool', type=ComponentType.LIBRARY, bom_ref='shared')
        standard = Standard(bom_ref='shared', name='STD')
        bom = Bom(components=[component])
        bom.metadata = BomMetaData(tools=ToolRepository(components=[tool_component]))
        bom._definitions.standards.add(standard)
        with self.assertRaises(DuplicateBomRefException) as error:
            with BomRefNormalizer.from_bom(bom):
                pass
        self.assertIn('shared', str(error.exception))

    def test_nested_license_ref_participates_in_uniqueness(self) -> None:
        license_ = DisjunctiveLicense(id='MIT', bom_ref='lic-ref')
        component = Component(
            name='comp', type=ComponentType.LIBRARY,
            bom_ref='lic-ref', licenses=[license_])
        bom = Bom(components=[component])
        with self.assertRaises(DuplicateBomRefException):
            with BomRefNormalizer.from_bom(bom):
                pass

    def test_missing_nested_license_ref_is_not_generated(self) -> None:
        license_ = DisjunctiveLicense(id='MIT')
        component = Component(
            name='comp', type=ComponentType.LIBRARY, licenses=[license_])
        bom = Bom(components=[component])
        with BomRefNormalizer.from_bom(bom):
            self.assertIsNone(license_.bom_ref.value)
            self.assertIsNotNone(component.bom_ref.value)

    def test_iter_all_identity_bom_refs_includes_primary_and_nested(self) -> None:
        license_ = DisjunctiveLicense(id='MIT', bom_ref='lic')
        component = Component(
            name='comp', type=ComponentType.LIBRARY,
            bom_ref='comp', licenses=[license_])
        bom = Bom(components=[component])
        values = [ref.value for ref in iter_all_identity_bom_refs(bom)]
        self.assertIn('comp', values)
        self.assertIn('lic', values)

    def test_legacy_discriminator_from_bom_still_works(self) -> None:
        component = Component(name='comp', type=ComponentType.LIBRARY)
        bom = Bom(components=[component])
        with BomRefDiscriminator.from_bom(bom):
            self.assertIsNotNone(component.bom_ref.value)
        self.assertIsNone(component.bom_ref.value)
