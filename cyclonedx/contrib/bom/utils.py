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

"""Bom related utilities"""

__all__ = [
    'BomRefDiscriminator',
    'BomRefNormalizer',
    'BomDependencyGraphFlatMerger',
]

from collections.abc import Iterable, Iterator
from itertools import chain
from random import random
from typing import TYPE_CHECKING, Any, Optional

from ...exception.model import DuplicateBomRefException
from ...model.bom_ref import BomRef
from ...model.dependency import Dependency

if TYPE_CHECKING:  # pragma: no cover
    from ...model.bom import Bom


def _iter_component_primary_refs(component: Any) -> Iterator[BomRef]:
    """Yield the identity BomRef of a component and of every nested component."""
    yield component.bom_ref
    for nested in component.components:
        yield from _iter_component_primary_refs(nested)


def _iter_component_nested_refs(component: Any) -> Iterator[BomRef]:
    """Yield the non-primary identity BomRefs nested in a component."""
    supplier = component.supplier
    if supplier is not None:
        yield from _iter_organizational_entity_refs(supplier)
    manufacturer = component.manufacturer
    if manufacturer is not None:
        yield from _iter_organizational_entity_refs(manufacturer)
    for author in component.authors:
        yield author.bom_ref
    for license_ in component.licenses:
        yield from _iter_license_refs(license_)
    evidence = component.evidence
    if evidence is not None:
        for occurrence in evidence.occurrences:
            yield occurrence.bom_ref
        for license_ in evidence.licenses:
            yield from _iter_license_refs(license_)
    for nested in component.components:
        yield from _iter_component_nested_refs(nested)


def _iter_organizational_entity_refs(entity: Any) -> Iterator[BomRef]:
    yield entity.bom_ref
    if entity.address is not None:
        yield entity.address.bom_ref
    for contact in entity.contacts:
        yield contact.bom_ref


def _iter_license_refs(license_: Any) -> Iterator[BomRef]:
    # DisjunctiveLicense, LicenseExpression and LicenseExpressionDetails all carry a bom_ref
    bom_ref = getattr(license_, 'bom_ref', None)
    if isinstance(bom_ref, BomRef):
        yield bom_ref
    details = getattr(license_, 'details', None)
    if details:
        for detail in details:
            detail_ref = getattr(detail, 'bom_ref', None)
            if isinstance(detail_ref, BomRef):
                yield detail_ref


def _iter_service_primary_refs(service: Any) -> Iterator[BomRef]:
    """Yield the identity BomRef of a service and of every nested service."""
    yield service.bom_ref
    for nested in service.services:
        yield from _iter_service_primary_refs(nested)


def _iter_service_nested_refs(service: Any) -> Iterator[BomRef]:
    """Yield the non-primary identity BomRefs nested in a service."""
    if service.provider is not None:
        yield from _iter_organizational_entity_refs(service.provider)
    for license_ in service.licenses:
        yield from _iter_license_refs(license_)
    for nested in service.services:
        yield from _iter_service_nested_refs(nested)


def _iter_tool_repository_primary_refs(tools: Any) -> Iterator[BomRef]:
    for component in tools.components:
        yield from _iter_component_primary_refs(component)
    for service in tools.services:
        yield from _iter_service_primary_refs(service)


def _iter_tool_repository_nested_refs(tools: Any) -> Iterator[BomRef]:
    for component in tools.components:
        yield from _iter_component_nested_refs(component)
    for service in tools.services:
        yield from _iter_service_nested_refs(service)


def _iter_standard_refs(standard: Any) -> Iterator[BomRef]:
    yield standard.bom_ref
    for requirement in standard.requirements:
        yield requirement.bom_ref
        # NOTE: `requirement.parent` and `level.requirements` are reference-only
        # BomRefs (fresh instances created from strings) - they point at identity
        # BomRefs and must not take part in uniqueness checks or value generation.
    for level in standard.levels:
        yield level.bom_ref


def iter_primary_bom_refs(bom: 'Bom') -> Iterator[BomRef]:
    """
    Iterate over the *primary* identity BomRefs of a Bom.

    These are the BomRefs of the Bom's main objects - components (including
    nested ones and the metadata component), services (including nested ones),
    components/services used as tools, vulnerabilities and the standards in
    ``definitions``. Missing values of these BomRefs are auto-filled during
    output, because the objects would otherwise lose their identity and the
    references pointing at them (dependency graph, ``affects`` and friends).
    """
    metadata = bom.metadata
    if metadata.component is not None:
        yield from _iter_component_primary_refs(metadata.component)
    yield from _iter_tool_repository_primary_refs(metadata.tools)
    for component in bom.components:
        yield from _iter_component_primary_refs(component)
    for service in bom.services:
        yield from _iter_service_primary_refs(service)
    for vulnerability in bom.vulnerabilities:
        yield vulnerability.bom_ref
        yield from _iter_tool_repository_primary_refs(vulnerability.tools)
    definitions = getattr(bom, '_definitions', None)
    if definitions is not None:
        for standard in definitions.standards:
            yield from _iter_standard_refs(standard)


def iter_nested_bom_refs(bom: 'Bom') -> Iterator[BomRef]:
    """
    Iterate over the *nested* identity BomRefs of a Bom.

    These are BomRefs on secondary objects - licenses, organizational
    entities/contacts/addresses and evidence occurrences. Missing values here
    are intentionally not auto-filled (the elements are simply rendered
    without a ``bom-ref``, matching historical behavior), but explicitly
    assigned values still must be unique within the whole Bom.
    """
    metadata = bom.metadata
    if metadata.component is not None:
        yield from _iter_component_nested_refs(metadata.component)
    yield from _iter_tool_repository_nested_refs(metadata.tools)
    for component in bom.components:
        yield from _iter_component_nested_refs(component)
    for service in bom.services:
        yield from _iter_service_nested_refs(service)
    for vulnerability in bom.vulnerabilities:
        yield from _iter_tool_repository_nested_refs(vulnerability.tools)
        credits = vulnerability.credits
        if credits is not None:
            for organization in credits.organizations:
                yield from _iter_organizational_entity_refs(organization)
            for individual in credits.individuals:
                yield individual.bom_ref


def iter_all_identity_bom_refs(bom: 'Bom') -> Iterator[BomRef]:
    """
    Iterate over all identity :class:`~cyclonedx.model.bom_ref.BomRef` objects
    that are rendered as ``bom-ref`` within the given Bom - primary ones first,
    nested ones afterwards.

    BomRefs that only appear as references (for example in dependency graphs,
    ``vulnerabilities[].affects`` or crypto properties) are not included - they
    must point at one of the identity BomRefs anyway.
    """
    yield from iter_primary_bom_refs(bom)
    yield from iter_nested_bom_refs(bom)


class BomRefNormalizer:
    """
    Ensure that all identity BomRef objects of a Bom have unique, non-empty
    :attr:`cyclonedx.model.bom_ref.BomRef.value` - without randomness and
    without silently renaming anything.

    *Primary* BomRefs (components, services, vulnerabilities, tools and
    standards - the objects references can point at) that are missing a value
    get a stable, reproducible value assigned. Missing values on *nested*
    secondary objects (licenses, contacts, addresses, evidence occurrences)
    are left untouched; those elements are simply rendered without a
    ``bom-ref``.

    Distinct BomRef objects that share the same value cause a
    :class:`~cyclonedx.exception.model.DuplicateBomRefException` that names the
    offending value. The very same BomRef instance being used in multiple
    places is allowed and not considered a duplicate.

    All changes are reverted by :meth:`reset()` or by using this class as a
    context manager, so the caller's Bom is never permanently modified.
    """

    def __init__(self, primary_bomrefs: Iterable[BomRef],
                 nested_bomrefs: Optional[Iterable[BomRef]] = None,
                 prefix: str = 'BomRef') -> None:
        # NOTE: do not use dict/set here, different BomRefs with same value
        #       have same hash and would shadow each other.
        self._primary_bomrefs = tuple((bomref, bomref.value) for bomref in primary_bomrefs)
        self._nested_bomrefs = tuple(
            (bomref, bomref.value) for bomref in (nested_bomrefs or ()))
        self._prefix = prefix
        self._missing_counter = 0

    def __enter__(self) -> None:
        self.discriminate()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.reset()

    def discriminate(self) -> None:
        """
        Enforce uniqueness across all identity
        :attr:`cyclonedx.model.bom_ref.BomRef.value`s.

        Every explicitly assigned value must belong to exactly one distinct
        BomRef object, otherwise a
        :class:`~cyclonedx.exception.model.DuplicateBomRefException` is raised
        (naming the offending value) and nothing is renamed. Primary BomRefs
        without a value get reproducible generated values.
        """
        known: dict[str, BomRef] = {}

        def register(value: str, bomref: BomRef) -> None:
            owner = known.get(value)
            if owner is None:
                known[value] = bomref
            elif owner is not bomref:
                raise DuplicateBomRefException(
                    f'Duplicate bom-ref {value!r}: the same bom-ref is used by '
                    'multiple distinct objects; every bom-ref must be unique within the BOM. '
                    f'Offending bom-ref: {value!r}')

        # Pass 1: register every explicitly assigned value, detect conflicts.
        for bomref, original_value in chain(self._primary_bomrefs, self._nested_bomrefs):
            if original_value is not None:
                register(original_value, bomref)
        # Pass 2: assign deterministic values to every missing primary BomRef.
        # Missing values on nested BomRefs are intentionally left alone.
        # The same BomRef instance may be shared by multiple objects, so track
        # instances that already got a value assigned.
        assigned: set[int] = set()
        for bomref, original_value in self._primary_bomrefs:
            if original_value is not None or id(bomref) in assigned:
                continue
            self._missing_counter += 1
            new_value = self._make_missing_value(self._missing_counter, known)
            bomref.value = new_value
            known[new_value] = bomref
            assigned.add(id(bomref))

    def reset(self) -> None:
        """
        Restore all :attr:`cyclonedx.model.bom_ref.BomRef.value`s to
        their original state.
        """
        for bomref, original_value in chain(self._primary_bomrefs, self._nested_bomrefs):
            bomref.value = original_value

    def _make_missing_value(self, index: int, known: dict[str, BomRef]) -> str:
        candidate = f'{self._prefix}.{index}'
        # practically never collides with an explicit value, but stay safe
        while candidate in known:
            index += 1
            candidate = f'{self._prefix}.{index}'
        return candidate

    @classmethod
    def from_bom(cls, bom: 'Bom', prefix: str = 'BomRef') -> 'BomRefNormalizer':
        """
        Create a normalizer for all identity BomRefs contained within a Bom.
        """
        return cls(iter_primary_bom_refs(bom), iter_nested_bom_refs(bom), prefix)


class BomRefDiscriminator:
    """
    Ensure that a collection of BomRef objects
    has unique, non‑empty :attr:`cyclonedx.model.bom_ref.BomRef.value`.

    The discriminator inspects each provided BomRef and assigns a newly
    generated identifier to any instance whose ``value`` is missing or
    duplicates an earlier one.
    All original values are preserved and can be restored via :meth:`reset()`
    or by using this class as a context manager.

    .. note::
        This class is kept for backwards compatibility. New code should use
        :class:`BomRefNormalizer`, which is reproducible and raises an explicit
        error on conflicting bom-ref values instead of renaming them.
    """

    def __init__(self, bomrefs: Iterable['BomRef'], prefix: str = 'BomRef') -> None:
        # NOTE: do not use dict/set here, different BomRefs with same value
        #       have same hash and would shadow each other.
        self._bomrefs = tuple((bomref, bomref.value) for bomref in bomrefs)
        self._prefix = prefix

    def __enter__(self) -> None:
        self.discriminate()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.reset()

    def discriminate(self) -> None:
        """
        Enforce uniqueness across all
        :attr:`cyclonedx.model.bom_ref.BomRef.value`s.

        Any BomRef whose ``value`` is ``None`` or duplicates a previously
        encountered value is assigned a newly generated unique identifier.
        """
        known_values = []
        for bomref, _ in self._bomrefs:
            value = bomref.value
            if value is None or value in known_values:
                value = self._make_unique()
                bomref.value = value
            known_values.append(value)

    def reset(self) -> None:
        """
        Restore all :attr:`cyclonedx.model.bom_ref.BomRef.value`s to
        their original state.
        """
        for bomref, original_value in self._bomrefs:
            bomref.value = original_value

    def _make_unique(self) -> str:
        return f'{self._prefix}{str(random())[1:]}{str(random())[1:]}'  # nosec B311

    @classmethod
    def from_bom(cls, bom: 'Bom', prefix: str = 'BomRef') -> 'BomRefDiscriminator':
        """
        Create a discriminator for all identity :class:`cyclonedx.model.bom_ref.BomRefs`
        contained within a Bom.
        """
        return cls(iter_all_identity_bom_refs(bom), prefix)


class BomDependencyGraphFlatMerger:
    """
    Context‑manager utility that temporarily flattens and merges all
    :attr:`cyclonedx.model.bom.Bom.dependencies`.

    When used as a context manager, the :class:`cyclonedx.model.bom.Bom`'s
    dependency graph is replaced with a flattened, merged representation
    for the duration of the ``with`` block and automatically restored
    afterward.
    """

    def __init__(self, bom: 'Bom') -> None:
        self._bom = bom
        # NOTE: do not use the getter - see `reset()` for reasons.
        self._deps = self._bom._dependencies

    def __enter__(self) -> None:
        self.flatten_merge()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.reset()

    def flatten_merge(self) -> None:
        """
        Flatten and merge all :attr:`cyclonedx.model.bom.Bom.dependencies`.

        This produces a non‑recursive, merged representation of the entire
        dependency graph and assigns it to the Bom.

        .. note::
           The original dependency graph is not modified. A new, flattened
           dependency structure is assigned to the Bom.
        """
        self._bom.dependencies = self._flatten_merge(self._deps)

    def reset(self) -> None:
        """
        Restore the :class:`cyclonedx.model.bom.Bom`'s dependency graph to
        its original state.

        .. note::
           This does not modify the dependency graph. It simply reassigns
           the original dependency collection back to the Bom.
        """
        # NOTE: not using the setter, which would create overhead,
        #       and - most importantly - this could cause deduplication of an existing malformed set.
        #       Just access the internal field directly!
        self._bom._dependencies = self._deps

    @staticmethod
    def _flatten_merge(deps: Iterable[Dependency]) -> Iterable[Dependency]:
        flat: dict['BomRef', list['BomRef']] = {}
        todos = list(deps)
        seen = set()
        while todos:
            todo = todos.pop()
            if (todo_id := id(todo)) in seen:
                continue
            seen.add(todo_id)
            ds = flat.setdefault(todo.ref, [])
            if todo_deps := todo.dependencies:
                ds.extend(d.ref for d in todo_deps)
                todos.extend(todo_deps)
        return (
            Dependency(br, (Dependency(d) for d in ds))
            for br, ds
            in flat.items()
        )
