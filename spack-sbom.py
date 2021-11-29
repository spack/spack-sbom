#!/usr/bin/env spack-python

# This is a proof of concept to generate a software bill of materials for
# a spack package. We can develop here and if it's desired, add the functions
# to spack to generate an SBOM always alongside a package. I'd propose to put
# in the metadata directory as .spack/sbom.json.

# https://www.ntia.gov/files/ntia/publications/howto_guide_for_sbom_generation_v1.pdf

import spack.main
import spack.config
import spack.spec

from datetime import datetime
import llnl.util.tty as tty
import uuid
import json

import re
import os
import sys

# We will use CycloneDX which is a simplified format approved by standards committees
# https://cyclonedx.org/docs/1.3/json
# https://cyclonedx.org/use-cases/
template = {

    # Specifies the format of the BOM. This helps to identify the file as CycloneDX
    # since BOMs do not have a filename convention nor does JSON schema support namespaces.
    "bomFormat": "CycloneDX",

    # The version of the CycloneDX specification a BOM is written to (starting at version 1.2)
    "specVersion": "1.3",
    "serialNumber": "",

    # The version WE are generating for the package - this would increment
    "version": 1,

    # Will be populated with metadata
    "metadata": {},
}


def generate_timestamp_now():
    return str(datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"))


def get_component(spec):
    """
    Given a spec, get a component for it.
    """
    # Let's take a simple approach - anything with "lib" is a library, otherwise application
    component_type = "lib" if "lib" in spec.package.name else "application"

    # Must be concrets
    spec.concretize()

    component = {
        # Note that "application" might also be a suitable choice
        # https://cyclonedx.org/docs/1.3/json/#metadata_component_type
        "type": component_type,

        # Specifies the scope of the component. If scope is not specified,
        #'required' scope should be assumed by the consumer of the BOM
        # Let's explicitly state that :)
        "scope": "required",

        # The name of the component. This will often be a shortened, single name of the component.
        # Examples: commons-lang3 and jquery
        "name": spec.package.name,

        # Associated mime-type. Spack doesn't have one officially, but this is what
        # I was using for oras push to an OCI registry
        "mime-type": "application/vnd.spack.package",

        # The grouping name or identifier. This will often be a shortened,
        # single name of the company or project that produced the component,
        # or the source package or domain name. Whitespace and special characters
        # should be avoided. Examples include: apache, org.apache.commons, and apache.org.
        "group": "spack.io",

        # The component version. The version should ideally comply with semantic versioning but is not enforced.
        "version": str(spec.version),
        # An optional identifier which can be used to reference the component elsewhere in the BOM. Every bom-ref should be unique.
        # We can use the build hash since it's unique to this spec

        "bom-ref": str(spec),
        # Excluded
        # publisher: The person(s) or organization(s) that published the component
        # author: The person(s) or organization(s) that authored the component
        # supplier: The organization that supplied the component. The supplier may often be the manufacturer, but may also be a distributor or repackager.
        # licenses: spack doesn't have enough metadata to make a call for sure on each
        # copyright: An optional copyright notice informing users of the underlying claims to copyright ownership in a published work.
        # purl: spack doesn't have these
        # swid: Specifies metadata and content for ISO-IEC 19770-2 Software Identification (SWID) Tags.
        # pedigree: Component pedigree is a way to document complex supply chain scenarios where
        # components are created, distributed, modified, redistributed, combined with other components, etc.
        # Pedigree supports viewing this complex chain from the beginning, the end, or anywhere in the middle.
        # It also provides a way to document variants where the exact relation may not be known.
        # components: I assume this means some kind of sub-component? Or component referenced within
        # the component elsewhere? For dependencies I'm going to describe them under dependencies.
        # evidence: Provides the ability to document evidence collected through various forms of extraction or analysis.
        # properites: extra name/value keypairs
    }

    # Specifies a description for the component
    # Only add if not empty!
    description = spec.package.format_doc()
    if description:
        component["description"] = description

    # Add hashes, whichever might exist
    # I looked for all unique hash types on 11/28
    # names = set()
    # for package in spack.repo.all_package_names():
    #    spec = spack.spec.Spec(package)
    #    for _, version in spec.package.versions.items():
    #        for alg, _ in version.items():
    #            names.add(alg)

    component["hashes"] = []
    for key, hashvalue in spec.package.versions.get(spec.version, {}).items():

        # Covers both sha256 and sha256sum
        if key.startswith("sha256"):
            component["hashes"].append({"alg": "SHA-256", "cotent": hashvalue})

    # External references?
    if spec.package.all_urls:
        component["externalReferences"] = []
        for url in spec.package.all_urls:
            component["externalReferences"].append({"type": "website", "url": url})

    # Finally, custom spack metadata (properties)
    component["properties"] = {
        "spack:build_hash": spec.build_hash(),
        "spack:dag_hash": spec.dag_hash(),
        "spack:spec": str(spec),
        "spack:build_spec": str(spec.build_spec),
        "spack:architecture": str(spec.architecture),
        "spack:variants": str(spec.variants),
        "spack:compiler": str(spec.compiler),
    }
    return component


def main(pkg):
    """
    Main generates the sbom based on best practices suggested in the guide.
    """
    bom = template.copy()
    spec = spack.spec.Spec(pkg)

    # Every BOM generated should have a unique serial number, even if the contents of the BOM
    # being generated have not changed over time. The process or tool responsible for
    # creating the BOM should create random UUID's for every BOM generated.
    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid4())

    # The date and time (timestamp) when the document was created.
    metadata = {"timestamp": generate_timestamp_now()}

    # The tool(s) used in the creation of the BOM.
    metadata["tools"] = [
        {
            "vendor": "Lawrence Livermore National Lab",
            "name": "Spack",
            "version": spack.main.get_version(),
        }
    ]

    # The person(s) who created the BOM. Authors are common in BOMs created through
    # manual processes. BOMs created through automated means may not have authors.
    metadata["authors"] = [
        {"name": "@vsoch", "email": "vsoch@users.noreply.github.com"}
    ]

    # The component that the BOM describes.
    metadata["component"] = get_component(spec)

    # Skipped:
    # manufacture: The organization that manufactured the component that the BOM describes.
    # supplier: The organization that supplied the component that the BOM describes.
    # The supplier may often be the manufacturer, but may also be a distributor or repackager.

    # Let's assume licenses under the bom is meant to describe spack, but not the component?
    metadata["licenses"] = [
        {"license": {"name": "MIT"}},
        {"license": {"name": "Apache-2.0"}},
    ]
    bom["metadata"] = metadata

    # We might also assume that properties on this level could be for spack
    # Could put spack properties here.
    deps = spec.dependencies()
    components = {}

    # Let's include all nested dependencies
    if deps:
        while deps:
            dep = deps.pop(0)
            deps = deps + dep.dependencies()

            if str(dep) not in components:
                components[str(dep)] = get_component(dep)

    if components:
        bom["components"] = components

    # Finally, add direct dependencies
    deps = spec.dependencies()
    if deps:
        bom["dependencies"] = []
        for dep in deps:
            # The bom-ref identifiers of the components that are dependencies of this dependency object.
            dependsOn = [str(x) for x in dep.dependencies()]
            bom["dependencies"].append({"ref": str(dep), "dependsOn": dependsOn})

    # Add an external reference for spack packages, GitHub, etc.
    bom["externalReferences"] = [
        {"type": "website", "url": "https://github.com/spack/spack"},
        {"type": "website", "url": "https://spack.github.io/packages"},
    ]
    print(json.dumps(bom, indent=4))


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("No package provided, will use zlib as an example.")
        package = "zlib"
    else:
        package = sys.argv[1]
    main(package)
