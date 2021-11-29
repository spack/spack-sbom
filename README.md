# Spack SBOM

A dummy example of generating a Software Bill of Materials ([SBOM](https://www.ntia.gov/SBOM)) for a spack package.

## Usage

Make sure that spack is on your path, and then do:

```bash
$ spack python spack-sbom.py zlib
```
```
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.3",
    "serialNumber": "urn:uuid:2dbecd32-b9bf-4679-bacd-87efba4ef557",
    "version": 1,
    "metadata": {
        "timestamp": "2021-11-28T18:56:11Z",
        "tools": [
            {
                "vendor": "Lawrence Livermore National Lab",
                "name": "Spack",
                "version": "0.16.0-3994-d9ea572a4b"
            }
        ],
        "authors": [
            {
                "name": "@vsoch",
                "email": "vsoch@users.noreply.github.com"
            }
        ],
        "component": {
            "type": "lib",
            "scope": "required",
            "name": "zlib",
            "mime-type": "application/vnd.spack.package",
            "group": "spack.io",
            "version": "1.2.11",
            "bom-ref": "zlib@1.2.11%gcc@9.3.0+optimize+pic+shared arch=linux-ubuntu20.04-skylake",
            "description": "A free, general-purpose, legally unencumbered lossless data-compression\nlibrary.\n",
            "hashes": [
                {
                    "alg": "SHA-256",
                    "cotent": "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1"
                }
            ],
            "externalReferences": [
                {
                    "type": "website",
                    "url": "https://zlib.net/fossils/zlib-1.2.11.tar.gz"
                }
            ],
            "properties": {
                "spack:build_hash": "3kmnsdv36qxm3slmcyrb326gkghsp6px",
                "spack:dag_hash": "3kmnsdv36qxm3slmcyrb326gkghsp6px",
                "spack:spec": "zlib@1.2.11%gcc@9.3.0+optimize+pic+shared arch=linux-ubuntu20.04-skylake",
                "spack:build_spec": "zlib@1.2.11%gcc@9.3.0+optimize+pic+shared arch=linux-ubuntu20.04-skylake",
                "spack:architecture": "linux-ubuntu20.04-skylake",
                "spack:variants": "+optimize+pic+shared",
                "spack:compiler": "gcc@9.3.0"
            }
        },
        "licenses": [
            {
                "license": {
                    "name": "MIT"
                }
            },
            {
                "license": {
                    "name": "Apache-2.0"
                }
            }
        ]
    },
    "externalReferences": [
        {
            "type": "website",
            "url": "https://github.com/spack/spack"
        },
        {
            "type": "website",
            "url": "https://spack.github.io/packages"
        }
    ]
}

```

A few [examples](examples) are provided, each generated as follows:

```bash
$ spack python spack-sbom.py zlib > examples/zlib.json
```

And that's it! If you have any feedback, please [open an issue](https://github.com/spack/spack-sbom/issues).
It's not clear if this will ever be desired by the spack community (and if so, when) so in the meantime it can
live here as a little spack script that is fairly easy to use if you need it. Please open an issue for discussion
or suggesting changes!
