import React, { useState } from 'react';
import {
    Container,
    Typography,
    Card,
    CardContent,
    CardActions,
    Button,
    Collapse,
    Table,
    TableBody,
    TableRow,
    TableCell,
    Link,
    Chip,
    Box,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';

const jsonData = {
    SchemaVersion: 2,
    CreatedAt: '2025-05-15T11:12:41.7112401+05:30',
    ArtifactName: '.',
    ArtifactType: 'filesystem',
    Metadata: {
        ImageConfig: {
            architecture: '',
            created: '0001-01-01T00:00:00Z',
            os: '',
            rootfs: {
                type: '',
                diff_ids: null,
            },
            config: {},
        },
    },
    Results: [
        {
            Target: 'package-lock.json',
            Class: 'lang-pkgs',
            Type: 'npm',
            Vulnerabilities: [
                {
                    VulnerabilityID: 'CVE-2025-27789',
                    PkgID: '@babel/helpers@7.23.7',
                    PkgName: '@babel/helpers',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/%40babel/helpers@7.23.7',
                        UID: 'ab8b119f0d6dd3f4',
                    },
                    InstalledVersion: '7.23.7',
                    FixedVersion: '7.26.10, 8.0.0-alpha.17',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2025-27789',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'Babel is a compiler for writing next generation JavaScript. When using ...',
                    Description:
                        "Babel is a compiler for writing next generation JavaScript. When using versions of Babel prior to 7.26.10 and 8.0.0-alpha.17 to compile regular expression named capturing groups, Babel will generate a polyfill for the `.replace` method that has quadratic complexity on some specific replacement pattern strings (i.e. the second argument passed to `.replace`). Generated code is vulnerable if all the following conditions are true: Using Babel to compile regular expression named capturing groups, using the `.replace` method on a regular expression that contains named capturing groups, and the code using untrusted strings as the second argument of `.replace`. This problem has been fixed in `@babel/helpers` and `@babel/runtime` 7.26.10 and 8.0.0-alpha.17. It's likely that individual users do not directly depend on `@babel/helpers`, and instead depend on `@babel/core` (which itself depends on `@babel/helpers`). Upgrading to `@babel/core` 7.26.10 is not required, but it guarantees use of a new enough `@babel/helpers` version. Note that just updating Babel dependencies is not enough; one will also need to re-compile the code. No known workarounds are available.",
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        ghsa: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 6.2,
                        },
                    },
                    References: [
                        'https://github.com/babel/babel',
                        'https://github.com/babel/babel/commit/d5952e80c0faa5ec20e35085531b6e572d31dad4',
                        'https://github.com/babel/babel/pull/17173',
                        'https://github.com/babel/babel/security/advisories/GHSA-968p-4wvh-cqc8',
                        'https://nvd.nist.gov/vuln/detail/CVE-2025-27789',
                    ],
                    PublishedDate: '2025-03-11T20:15:18.33Z',
                    LastModifiedDate: '2025-03-11T20:15:18.33Z',
                },
                {
                    VulnerabilityID: 'CVE-2025-27789',
                    PkgID: '@babel/runtime@7.22.10',
                    PkgName: '@babel/runtime',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/%40babel/runtime@7.22.10',
                        UID: '29a4adb7553e8ee5',
                    },
                    InstalledVersion: '7.22.10',
                    FixedVersion: '7.26.10, 8.0.0-alpha.17',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2025-27789',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'Babel is a compiler for writing next generation JavaScript. When using ...',
                    Description:
                        "Babel is a compiler for writing next generation JavaScript. When using versions of Babel prior to 7.26.10 and 8.0.0-alpha.17 to compile regular expression named capturing groups, Babel will generate a polyfill for the `.replace` method that has quadratic complexity on some specific replacement pattern strings (i.e. the second argument passed to `.replace`). Generated code is vulnerable if all the following conditions are true: Using Babel to compile regular expression named capturing groups, using the `.replace` method on a regular expression that contains named capturing groups, and the code using untrusted strings as the second argument of `.replace`. This problem has been fixed in `@babel/helpers` and `@babel/runtime` 7.26.10 and 8.0.0-alpha.17. It's likely that individual users do not directly depend on `@babel/helpers`, and instead depend on `@babel/core` (which itself depends on `@babel/helpers`). Upgrading to `@babel/core` 7.26.10 is not required, but it guarantees use of a new enough `@babel/helpers` version. Note that just updating Babel dependencies is not enough; one will also need to re-compile the code. No known workarounds are available.",
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        ghsa: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 6.2,
                        },
                    },
                    References: [
                        'https://github.com/babel/babel',
                        'https://github.com/babel/babel/commit/d5952e80c0faa5ec20e35085531b6e572d31dad4',
                        'https://github.com/babel/babel/pull/17173',
                        'https://github.com/babel/babel/security/advisories/GHSA-968p-4wvh-cqc8',
                        'https://nvd.nist.gov/vuln/detail/CVE-2025-27789',
                    ],
                    PublishedDate: '2025-03-11T20:15:18.33Z',
                    LastModifiedDate: '2025-03-11T20:15:18.33Z',
                },
                {
                    VulnerabilityID: 'CVE-2025-27789',
                    PkgID: '@babel/runtime-corejs3@7.22.10',
                    PkgName: '@babel/runtime-corejs3',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/%40babel/runtime-corejs3@7.22.10',
                        UID: '59b2c7eca07753ff',
                    },
                    InstalledVersion: '7.22.10',
                    FixedVersion: '7.26.10, 8.0.0-alpha.17',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2025-27789',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'Babel is a compiler for writing next generation JavaScript. When using ...',
                    Description:
                        "Babel is a compiler for writing next generation JavaScript. When using versions of Babel prior to 7.26.10 and 8.0.0-alpha.17 to compile regular expression named capturing groups, Babel will generate a polyfill for the `.replace` method that has quadratic complexity on some specific replacement pattern strings (i.e. the second argument passed to `.replace`). Generated code is vulnerable if all the following conditions are true: Using Babel to compile regular expression named capturing groups, using the `.replace` method on a regular expression that contains named capturing groups, and the code using untrusted strings as the second argument of `.replace`. This problem has been fixed in `@babel/helpers` and `@babel/runtime` 7.26.10 and 8.0.0-alpha.17. It's likely that individual users do not directly depend on `@babel/helpers`, and instead depend on `@babel/core` (which itself depends on `@babel/helpers`). Upgrading to `@babel/core` 7.26.10 is not required, but it guarantees use of a new enough `@babel/helpers` version. Note that just updating Babel dependencies is not enough; one will also need to re-compile the code. No known workarounds are available.",
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        ghsa: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 6.2,
                        },
                    },
                    References: [
                        'https://github.com/babel/babel',
                        'https://github.com/babel/babel/commit/d5952e80c0faa5ec20e35085531b6e572d31dad4',
                        'https://github.com/babel/babel/pull/17173',
                        'https://github.com/babel/babel/security/advisories/GHSA-968p-4wvh-cqc8',
                        'https://nvd.nist.gov/vuln/detail/CVE-2025-27789',
                    ],
                    PublishedDate: '2025-03-11T20:15:18.33Z',
                    LastModifiedDate: '2025-03-11T20:15:18.33Z',
                },
                {
                    VulnerabilityID: 'CVE-2025-27152',
                    PkgID: 'axios@0.22.0',
                    PkgName: 'axios',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/axios@0.22.0',
                        UID: '2597692330fff2c5',
                    },
                    InstalledVersion: '0.22.0',
                    FixedVersion: '1.8.2, 0.30.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2025-27152',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'axios: Possible SSRF and Credential Leakage via Absolute URL in axios Requests',
                    Description:
                        'axios is a promise based HTTP client for the browser and node.js. The issue occurs when passing absolute URLs rather than protocol-relative URLs to axios. Even if ⁠baseURL is set, axios sends the request to the specified absolute URL, potentially causing SSRF and credential leakage. This issue impacts both server-side and client-side usage of axios. This issue is fixed in 1.8.2.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-918'],
                    VendorSeverity: {
                        ghsa: 3,
                        redhat: 2,
                    },
                    CVSS: {
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                            V3Score: 5.3,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2025-27152',
                        'https://github.com/axios/axios',
                        'https://github.com/axios/axios/commit/02c3c69ced0f8fd86407c23203835892313d7fde',
                        'https://github.com/axios/axios/commit/fb8eec214ce7744b5ca787f2c3b8339b2f54b00f',
                        'https://github.com/axios/axios/issues/6463',
                        'https://github.com/axios/axios/pull/6829',
                        'https://github.com/axios/axios/releases/tag/v1.8.2',
                        'https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6',
                        'https://nvd.nist.gov/vuln/detail/CVE-2025-27152',
                        'https://www.cve.org/CVERecord?id=CVE-2025-27152',
                    ],
                    PublishedDate: '2025-03-07T16:15:38.773Z',
                    LastModifiedDate: '2025-03-07T20:15:38.56Z',
                },
                {
                    VulnerabilityID: 'CVE-2023-45857',
                    PkgID: 'axios@0.22.0',
                    PkgName: 'axios',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/axios@0.22.0',
                        UID: '2597692330fff2c5',
                    },
                    InstalledVersion: '0.22.0',
                    FixedVersion: '1.6.0, 0.28.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-45857',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'axios: exposure of confidential data stored in cookies',
                    Description:
                        'An issue discovered in Axios 1.5.1 inadvertently reveals the confidential XSRF-TOKEN stored in cookies by including it in the HTTP header X-XSRF-TOKEN for every request made to any host allowing attackers to view sensitive information.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-352'],
                    VendorSeverity: {
                        ghsa: 2,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
                            V3Score: 6.5,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
                            V3Score: 6.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
                            V3Score: 6.5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2023-45857',
                        'https://github.com/axios/axios',
                        'https://github.com/axios/axios/commit/2755df562b9c194fba6d8b609a383443f6a6e967',
                        'https://github.com/axios/axios/commit/96ee232bd3ee4de2e657333d4d2191cd389e14d0',
                        'https://github.com/axios/axios/issues/6006',
                        'https://github.com/axios/axios/issues/6022',
                        'https://github.com/axios/axios/pull/6028',
                        'https://github.com/axios/axios/pull/6091',
                        'https://github.com/axios/axios/releases/tag/v0.28.0',
                        'https://github.com/axios/axios/releases/tag/v1.6.0',
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-45857',
                        'https://security.netapp.com/advisory/ntap-20240621-0006',
                        'https://security.netapp.com/advisory/ntap-20240621-0006/',
                        'https://security.snyk.io/vuln/SNYK-JS-AXIOS-6032459',
                        'https://www.cve.org/CVERecord?id=CVE-2023-45857',
                    ],
                    PublishedDate: '2023-11-08T21:15:08.55Z',
                    LastModifiedDate: '2024-11-21T08:27:30.04Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-45590',
                    PkgID: 'body-parser@1.20.1',
                    PkgName: 'body-parser',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/body-parser@1.20.1',
                        UID: 'cd7a1d2ad50862c6',
                    },
                    InstalledVersion: '1.20.1',
                    FixedVersion: '1.20.3',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-45590',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'body-parser: Denial of Service Vulnerability in body-parser',
                    Description:
                        'body-parser is Node.js body parsing middleware. body-parser \u003c1.20.3 is vulnerable to denial of service when url encoding is enabled. A malicious actor using a specially crafted payload could flood the server with a large number of requests, resulting in denial of service. This issue is patched in 1.20.3.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-405'],
                    VendorSeverity: {
                        azure: 3,
                        'cbl-mariner': 3,
                        ghsa: 3,
                        nvd: 3,
                        redhat: 3,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-45590',
                        'https://github.com/expressjs/body-parser',
                        'https://github.com/expressjs/body-parser/commit/b2695c4450f06ba3b0ccf48d872a229bb41c9bce',
                        'https://github.com/expressjs/body-parser/security/advisories/GHSA-qwcr-r2fm-qrc7',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-45590',
                        'https://www.cve.org/CVERecord?id=CVE-2024-45590',
                    ],
                    PublishedDate: '2024-09-10T16:15:21.083Z',
                    LastModifiedDate: '2024-09-20T16:26:44.977Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-47764',
                    PkgID: 'cookie@0.5.0',
                    PkgName: 'cookie',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/cookie@0.5.0',
                        UID: 'f16ce33d676ac996',
                    },
                    InstalledVersion: '0.5.0',
                    FixedVersion: '0.7.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-47764',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'cookie: cookie accepts cookie name, path, and domain with out of bounds characters',
                    Description:
                        'cookie is a basic HTTP cookie parser and serializer for HTTP servers. The cookie name could be used to set other fields of the cookie, resulting in an unexpected cookie value. A similar escape can be used for path and domain, which could be abused to alter other fields of the cookie. Upgrade to 0.7.0, which updates the validation for name, path, and domain.',
                    Severity: 'LOW',
                    CweIDs: ['CWE-74'],
                    VendorSeverity: {
                        'cbl-mariner': 2,
                        ghsa: 1,
                        redhat: 1,
                    },
                    CVSS: {
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N',
                            V3Score: 3.7,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-47764',
                        'https://github.com/jshttp/cookie',
                        'https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c',
                        'https://github.com/jshttp/cookie/pull/167',
                        'https://github.com/jshttp/cookie/security/advisories/GHSA-pxg6-pf52-xh8x',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-47764',
                        'https://www.cve.org/CVERecord?id=CVE-2024-47764',
                    ],
                    PublishedDate: '2024-10-04T20:15:07.31Z',
                    LastModifiedDate: '2024-10-07T17:48:28.117Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-47764',
                    PkgID: 'cookie@0.6.0',
                    PkgName: 'cookie',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/cookie@0.6.0',
                        UID: '78cb3ad446a0061e',
                    },
                    InstalledVersion: '0.6.0',
                    FixedVersion: '0.7.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-47764',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'cookie: cookie accepts cookie name, path, and domain with out of bounds characters',
                    Description:
                        'cookie is a basic HTTP cookie parser and serializer for HTTP servers. The cookie name could be used to set other fields of the cookie, resulting in an unexpected cookie value. A similar escape can be used for path and domain, which could be abused to alter other fields of the cookie. Upgrade to 0.7.0, which updates the validation for name, path, and domain.',
                    Severity: 'LOW',
                    CweIDs: ['CWE-74'],
                    VendorSeverity: {
                        'cbl-mariner': 2,
                        ghsa: 1,
                        redhat: 1,
                    },
                    CVSS: {
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N',
                            V3Score: 3.7,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-47764',
                        'https://github.com/jshttp/cookie',
                        'https://github.com/jshttp/cookie/commit/e10042845354fea83bd8f34af72475eed1dadf5c',
                        'https://github.com/jshttp/cookie/pull/167',
                        'https://github.com/jshttp/cookie/security/advisories/GHSA-pxg6-pf52-xh8x',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-47764',
                        'https://www.cve.org/CVERecord?id=CVE-2024-47764',
                    ],
                    PublishedDate: '2024-10-04T20:15:07.31Z',
                    LastModifiedDate: '2024-10-07T17:48:28.117Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-21538',
                    PkgID: 'cross-spawn@7.0.3',
                    PkgName: 'cross-spawn',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/cross-spawn@7.0.3',
                        UID: '4877879e18e78dc5',
                    },
                    InstalledVersion: '7.0.3',
                    FixedVersion: '7.0.5, 6.0.6',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-21538',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'cross-spawn: regular expression denial of service',
                    Description:
                        'Versions of the package cross-spawn before 7.0.5 are vulnerable to Regular Expression Denial of Service (ReDoS) due to improper input sanitization. An attacker can increase the CPU usage and crash the program by crafting a very large and well crafted string.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        amazon: 2,
                        azure: 3,
                        'cbl-mariner': 3,
                        ghsa: 3,
                        redhat: 1,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:H',
                            V3Score: 4.4,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-21538',
                        'https://github.com/moxystudio/node-cross-spawn',
                        'https://github.com/moxystudio/node-cross-spawn/commit/5ff3a07d9add449021d806e45c4168203aa833ff',
                        'https://github.com/moxystudio/node-cross-spawn/commit/640d391fde65388548601d95abedccc12943374f',
                        'https://github.com/moxystudio/node-cross-spawn/commit/d35c865b877d2f9ded7c1ed87521c2fdb689c8dd',
                        'https://github.com/moxystudio/node-cross-spawn/issues/165',
                        'https://github.com/moxystudio/node-cross-spawn/pull/160',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-21538',
                        'https://security.snyk.io/vuln/SNYK-JAVA-ORGWEBJARSNPM-8366349',
                        'https://security.snyk.io/vuln/SNYK-JS-CROSSSPAWN-8303230',
                        'https://www.cve.org/CVERecord?id=CVE-2024-21538',
                    ],
                    PublishedDate: '2024-11-08T05:15:06.453Z',
                    LastModifiedDate: '2024-11-19T14:15:17.627Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-29041',
                    PkgID: 'express@4.18.2',
                    PkgName: 'express',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/express@4.18.2',
                        UID: 'f80a9db5140f2841',
                    },
                    InstalledVersion: '4.18.2',
                    FixedVersion: '4.19.2, 5.0.0-beta.3',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-29041',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'express: cause malformed URLs to be evaluated',
                    Description:
                        'Express.js minimalist web framework for node. Versions of Express.js prior to 4.19.0 and all pre-release alpha and beta versions of 5.0 are affected by an open redirect vulnerability using malformed URLs. When a user of Express performs a redirect using a user-provided URL Express performs an encode [using `encodeurl`](https://github.com/pillarjs/encodeurl) on the contents before passing it to the `location` header. This can cause malformed URLs to be evaluated in unexpected ways by common redirect allow list implementations in Express applications, leading to an Open Redirect via bypass of a properly implemented allow list. The main method impacted is `res.location()` but this is also called from within `res.redirect()`. The vulnerability is fixed in 4.19.2 and 5.0.0-beta.3.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-601', 'CWE-1286'],
                    VendorSeverity: {
                        'cbl-mariner': 2,
                        ghsa: 2,
                        redhat: 3,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-29041',
                        'https://expressjs.com/en/4x/api.html#res.location',
                        'https://github.com/expressjs/express',
                        'https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd',
                        'https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94',
                        'https://github.com/expressjs/express/pull/5539',
                        'https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc',
                        'https://github.com/koajs/koa/issues/1800',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-29041',
                        'https://www.cve.org/CVERecord?id=CVE-2024-29041',
                    ],
                    PublishedDate: '2024-03-25T21:15:46.847Z',
                    LastModifiedDate: '2024-11-21T09:07:26.023Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-43796',
                    PkgID: 'express@4.18.2',
                    PkgName: 'express',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/express@4.18.2',
                        UID: 'f80a9db5140f2841',
                    },
                    InstalledVersion: '4.18.2',
                    FixedVersion: '4.20.0, 5.0.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-43796',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'express: Improper Input Handling in Express Redirects',
                    Description:
                        'Express.js minimalist web framework for node. In express \u003c 4.20.0, passing untrusted user input - even after sanitizing it - to response.redirect() may execute untrusted code. This issue is patched in express 4.20.0.',
                    Severity: 'LOW',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        azure: 2,
                        'cbl-mariner': 2,
                        ghsa: 1,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L',
                            V3Score: 5,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 4.7,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L',
                            V3Score: 5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-43796',
                        'https://github.com/expressjs/express',
                        'https://github.com/expressjs/express/commit/54271f69b511fea198471e6ff3400ab805d6b553',
                        'https://github.com/expressjs/express/security/advisories/GHSA-qw6h-vgh9-j6wx',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-43796',
                        'https://www.cve.org/CVERecord?id=CVE-2024-43796',
                    ],
                    PublishedDate: '2024-09-10T15:15:17.51Z',
                    LastModifiedDate: '2024-09-20T16:07:47.997Z',
                },
                {
                    VulnerabilityID: 'CVE-2023-26159',
                    PkgID: 'follow-redirects@1.15.2',
                    PkgName: 'follow-redirects',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/follow-redirects@1.15.2',
                        UID: 'a88ce2613f5ca95',
                    },
                    InstalledVersion: '1.15.2',
                    FixedVersion: '1.15.4',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-26159',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'follow-redirects: Improper Input Validation due to the improper handling of URLs by the url.parse()',
                    Description:
                        'Versions of the package follow-redirects before 1.15.4 are vulnerable to Improper Input Validation due to the improper handling of URLs by the url.parse() function. When new URL() throws an error, it can be manipulated to misinterpret the hostname. An attacker could exploit this weakness to redirect traffic to a malicious site, potentially leading to information disclosure, phishing attacks, or other security breaches.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-20', 'CWE-601'],
                    VendorSeverity: {
                        azure: 2,
                        'cbl-mariner': 2,
                        ghsa: 2,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2023-26159',
                        'https://github.com/follow-redirects/follow-redirects',
                        'https://github.com/follow-redirects/follow-redirects/commit/7a6567e16dfa9ad18a70bfe91784c28653fbf19d',
                        'https://github.com/follow-redirects/follow-redirects/issues/235',
                        'https://github.com/follow-redirects/follow-redirects/pull/236',
                        'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZZ425BFKNBQ6AK7I5SAM56TWON5OF2XM',
                        'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZZ425BFKNBQ6AK7I5SAM56TWON5OF2XM/',
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-26159',
                        'https://security.snyk.io/vuln/SNYK-JS-FOLLOWREDIRECTS-6141137',
                        'https://www.cve.org/CVERecord?id=CVE-2023-26159',
                    ],
                    PublishedDate: '2024-01-02T05:15:08.63Z',
                    LastModifiedDate: '2024-11-21T07:50:54.353Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-28849',
                    PkgID: 'follow-redirects@1.15.2',
                    PkgName: 'follow-redirects',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/follow-redirects@1.15.2',
                        UID: 'a88ce2613f5ca95',
                    },
                    InstalledVersion: '1.15.2',
                    FixedVersion: '1.15.6',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-28849',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'follow-redirects: Possible credential leak',
                    Description:
                        "follow-redirects is an open source, drop-in replacement for Node's `http` and `https` modules that automatically follows redirects. In affected versions follow-redirects only clears authorization header during cross-domain redirect, but keep the proxy-authentication header which contains credentials too. This vulnerability may lead to credentials leak, but has been addressed in version 1.15.6. Users are advised to upgrade. There are no known workarounds for this vulnerability.",
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-200'],
                    VendorSeverity: {
                        'cbl-mariner': 2,
                        ghsa: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
                            V3Score: 6.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
                            V3Score: 6.5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-28849',
                        'https://fetch.spec.whatwg.org/#authentication-entries',
                        'https://github.com/follow-redirects/follow-redirects',
                        'https://github.com/follow-redirects/follow-redirects/commit/c4f847f85176991f95ab9c88af63b1294de8649b',
                        'https://github.com/follow-redirects/follow-redirects/security/advisories/GHSA-cxjh-pqwp-8mfp',
                        'https://github.com/psf/requests/issues/1885',
                        'https://hackerone.com/reports/2390009',
                        'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VOIF4EPQUCKDBEVTGRQDZ3CGTYQHPO7Z',
                        'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VOIF4EPQUCKDBEVTGRQDZ3CGTYQHPO7Z/',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-28849',
                        'https://www.cve.org/CVERecord?id=CVE-2024-28849',
                    ],
                    PublishedDate: '2024-03-14T17:15:52.097Z',
                    LastModifiedDate: '2024-11-21T09:07:02.53Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-21536',
                    PkgID: 'http-proxy-middleware@2.0.6',
                    PkgName: 'http-proxy-middleware',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/http-proxy-middleware@2.0.6',
                        UID: '9e5ea8108904f5e8',
                    },
                    InstalledVersion: '2.0.6',
                    FixedVersion: '2.0.7, 3.0.3',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-21536',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'http-proxy-middleware: Denial of Service',
                    Description:
                        'Versions of the package http-proxy-middleware before 2.0.7, from 3.0.0 and before 3.0.3 are vulnerable to Denial of Service (DoS) due to an UnhandledPromiseRejection error thrown by micromatch. An attacker could kill the Node.js process and crash the server by making requests to certain paths.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-400'],
                    VendorSeverity: {
                        ghsa: 3,
                        nvd: 3,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-21536',
                        'https://gist.github.com/mhassan1/28be67266d82a53708ed59ce5dc3c94a',
                        'https://github.com/chimurai/http-proxy-middleware',
                        'https://github.com/chimurai/http-proxy-middleware/commit/0b4274e8cc9e9a2c5a06f35fbf456ccfcebc55a5',
                        'https://github.com/chimurai/http-proxy-middleware/commit/788b21e4aff38332d6319557d4a5b1b13b1f9a22',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-21536',
                        'https://security.snyk.io/vuln/SNYK-JS-HTTPPROXYMIDDLEWARE-8229906',
                        'https://www.cve.org/CVERecord?id=CVE-2024-21536',
                    ],
                    PublishedDate: '2024-10-19T05:15:13.097Z',
                    LastModifiedDate: '2024-11-01T18:03:15.897Z',
                },
                {
                    VulnerabilityID: 'CVE-2025-32996',
                    PkgID: 'http-proxy-middleware@2.0.6',
                    PkgName: 'http-proxy-middleware',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/http-proxy-middleware@2.0.6',
                        UID: '9e5ea8108904f5e8',
                    },
                    InstalledVersion: '2.0.6',
                    FixedVersion: '2.0.8, 3.0.4',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2025-32996',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'http-proxy-middleware: Always-Incorrect Control Flow Implementation in http-proxy-middleware',
                    Description:
                        'In http-proxy-middleware before 2.0.8 and 3.x before 3.0.4, writeBody can be called twice because "else if" is not used.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-670'],
                    VendorSeverity: {
                        ghsa: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L',
                            V3Score: 4,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:L',
                            V3Score: 4,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2025-32996',
                        'https://github.com/chimurai/http-proxy-middleware',
                        'https://github.com/chimurai/http-proxy-middleware/commit/020976044d113fc0bcbbaf995e91d05e2829a145',
                        'https://github.com/chimurai/http-proxy-middleware/pull/1089',
                        'https://github.com/chimurai/http-proxy-middleware/releases/tag/v2.0.8',
                        'https://github.com/chimurai/http-proxy-middleware/releases/tag/v3.0.4',
                        'https://nvd.nist.gov/vuln/detail/CVE-2025-32996',
                        'https://www.cve.org/CVERecord?id=CVE-2025-32996',
                    ],
                    PublishedDate: '2025-04-15T03:15:18.21Z',
                    LastModifiedDate: '2025-04-15T18:39:27.967Z',
                },
                {
                    VulnerabilityID: 'CVE-2025-32997',
                    PkgID: 'http-proxy-middleware@2.0.6',
                    PkgName: 'http-proxy-middleware',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/http-proxy-middleware@2.0.6',
                        UID: '9e5ea8108904f5e8',
                    },
                    InstalledVersion: '2.0.6',
                    FixedVersion: '2.0.9, 3.0.5',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2025-32997',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'http-proxy-middleware: Improper Check for Unusual or Exceptional Conditions in http-proxy-middleware',
                    Description:
                        'In http-proxy-middleware before 2.0.9 and 3.x before 3.0.5, fixRequestBody proceeds even if bodyParser has failed.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-754'],
                    VendorSeverity: {
                        ghsa: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N',
                            V3Score: 4,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:L/A:N',
                            V3Score: 4,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2025-32997',
                        'https://github.com/chimurai/http-proxy-middleware',
                        'https://github.com/chimurai/http-proxy-middleware/commit/1bdccbeec243850f1d2bb50ea0ff2151e725d67e',
                        'https://github.com/chimurai/http-proxy-middleware/pull/1096',
                        'https://github.com/chimurai/http-proxy-middleware/releases/tag/v2.0.9',
                        'https://github.com/chimurai/http-proxy-middleware/releases/tag/v3.0.5',
                        'https://nvd.nist.gov/vuln/detail/CVE-2025-32997',
                        'https://www.cve.org/CVERecord?id=CVE-2025-32997',
                    ],
                    PublishedDate: '2025-04-15T03:15:18.363Z',
                    LastModifiedDate: '2025-04-15T18:39:27.967Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-4067',
                    PkgID: 'micromatch@4.0.5',
                    PkgName: 'micromatch',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/micromatch@4.0.5',
                        UID: '9290ea2ba4d4fed5',
                    },
                    InstalledVersion: '4.0.5',
                    FixedVersion: '4.0.8',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-4067',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'micromatch: vulnerable to Regular Expression Denial of Service',
                    Description:
                        "The NPM package `micromatch` prior to 4.0.8 is vulnerable to Regular Expression Denial of Service (ReDoS). The vulnerability occurs in `micromatch.braces()` in `index.js` because the pattern `.*` will greedily match anything. By passing a malicious payload, the pattern matching will keep backtracking to the input while it doesn't find the closing bracket. As the input size increases, the consumption time will also increase until it causes the application to hang or slow down. There was a merged fix but further testing shows the issue persists. This issue should be mitigated by using a safe pattern that won't start backtracking the regular expression due to greedy matching. This issue was fixed in version 4.0.8.",
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        ghsa: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
                            V3Score: 5.3,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-4067',
                        'https://advisory.checkmarx.net/advisory/CVE-2024-4067',
                        'https://advisory.checkmarx.net/advisory/CVE-2024-4067/',
                        'https://devhub.checkmarx.com/cve-details/CVE-2024-4067',
                        'https://devhub.checkmarx.com/cve-details/CVE-2024-4067/',
                        'https://github.com/micromatch/micromatch',
                        'https://github.com/micromatch/micromatch/blob/2c56a8604b68c1099e7bc0f807ce0865a339747a/index.js#L448',
                        'https://github.com/micromatch/micromatch/commit/03aa8052171e878897eee5d7bb2ae0ae83ec2ade',
                        'https://github.com/micromatch/micromatch/commit/500d5d6f42f0e8dfa1cb5464c6cb420b1b6aaaa0',
                        'https://github.com/micromatch/micromatch/issues/243',
                        'https://github.com/micromatch/micromatch/pull/247',
                        'https://github.com/micromatch/micromatch/pull/266',
                        'https://github.com/micromatch/micromatch/releases/tag/4.0.8',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-4067',
                        'https://www.cve.org/CVERecord?id=CVE-2024-4067',
                    ],
                    PublishedDate: '2024-05-14T15:42:47.947Z',
                    LastModifiedDate: '2024-11-21T09:42:07.587Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-55565',
                    PkgID: 'nanoid@3.3.6',
                    PkgName: 'nanoid',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/nanoid@3.3.6',
                        UID: 'e270007cf01b8921',
                    },
                    InstalledVersion: '3.3.6',
                    FixedVersion: '5.0.9, 3.3.8',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-55565',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'nanoid: nanoid mishandles non-integer values',
                    Description:
                        'nanoid (aka Nano ID) before 5.0.9 mishandles non-integer values. 3.3.8 is also a fixed version.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-835'],
                    VendorSeverity: {
                        ghsa: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N',
                            V3Score: 4.3,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 6.5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-55565',
                        'https://github.com/ai/nanoid',
                        'https://github.com/ai/nanoid/compare/3.3.7...3.3.8',
                        'https://github.com/ai/nanoid/pull/510',
                        'https://github.com/ai/nanoid/releases/tag/5.0.9',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-55565',
                        'https://www.cve.org/CVERecord?id=CVE-2024-55565',
                    ],
                    PublishedDate: '2024-12-09T02:15:19.607Z',
                    LastModifiedDate: '2024-12-12T19:15:13.67Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-45296',
                    PkgID: 'path-to-regexp@0.1.7',
                    PkgName: 'path-to-regexp',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/path-to-regexp@0.1.7',
                        UID: 'c439c19100f5adde',
                    },
                    InstalledVersion: '0.1.7',
                    FixedVersion: '1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-45296',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'path-to-regexp: Backtracking regular expressions cause ReDoS',
                    Description:
                        'path-to-regexp turns path strings into a regular expressions. In certain cases, path-to-regexp will output a regular expression that can be exploited to cause poor performance. Because JavaScript is single threaded and regex matching runs on the main thread, poor performance will block the event loop and lead to a DoS. The bad regular expression is generated any time you have two parameters within a single segment, separated by something that is not a period (.). For users of 0.1, upgrade to 0.1.10. All other users should upgrade to 8.0.0.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        'cbl-mariner': 3,
                        ghsa: 3,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
                            V3Score: 5.3,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-45296',
                        'https://github.com/pillarjs/path-to-regexp',
                        'https://github.com/pillarjs/path-to-regexp/commit/29b96b4a1de52824e1ca0f49a701183cc4ed476f',
                        'https://github.com/pillarjs/path-to-regexp/commit/60f2121e9b66b7b622cc01080df0aabda9eedee6',
                        'https://github.com/pillarjs/path-to-regexp/commit/925ac8e3c5780b02f58cbd4e52f95da8ad2ac485',
                        'https://github.com/pillarjs/path-to-regexp/commit/d31670ae8f6e69cbfd56e835742195b7d10942ef',
                        'https://github.com/pillarjs/path-to-regexp/commit/f1253b47b347dcb909e3e80b0eb2649109e59894',
                        'https://github.com/pillarjs/path-to-regexp/releases/tag/v6.3.0',
                        'https://github.com/pillarjs/path-to-regexp/security/advisories/GHSA-9wv6-86v2-598j',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-45296',
                        'https://security.netapp.com/advisory/ntap-20250124-0001',
                        'https://security.netapp.com/advisory/ntap-20250124-0001/',
                        'https://www.cve.org/CVERecord?id=CVE-2024-45296',
                    ],
                    PublishedDate: '2024-09-09T19:15:13.33Z',
                    LastModifiedDate: '2025-01-24T20:15:32.68Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-52798',
                    PkgID: 'path-to-regexp@0.1.7',
                    PkgName: 'path-to-regexp',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/path-to-regexp@0.1.7',
                        UID: 'c439c19100f5adde',
                    },
                    InstalledVersion: '0.1.7',
                    FixedVersion: '0.1.12',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-52798',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'path-to-regexp: path-to-regexp Unpatched `path-to-regexp` ReDoS in 0.1.x',
                    Description:
                        'path-to-regexp turns path strings into a regular expressions. In certain cases, path-to-regexp will output a regular expression that can be exploited to cause poor performance. The regular expression that is vulnerable to backtracking can be generated in the 0.1.x release of path-to-regexp. Upgrade to 0.1.12. This vulnerability exists because of an incomplete fix for CVE-2024-45296.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        'cbl-mariner': 2,
                        ghsa: 3,
                        redhat: 2,
                    },
                    CVSS: {
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
                            V3Score: 5.3,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-52798',
                        'https://blakeembrey.com/posts/2024-09-web-redos',
                        'https://github.com/pillarjs/path-to-regexp',
                        'https://github.com/pillarjs/path-to-regexp/commit/f01c26a013b1889f0c217c643964513acf17f6a4',
                        'https://github.com/pillarjs/path-to-regexp/security/advisories/GHSA-rhx6-c78j-4q9w',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-52798',
                        'https://security.netapp.com/advisory/ntap-20250124-0002',
                        'https://security.netapp.com/advisory/ntap-20250124-0002/',
                        'https://www.cve.org/CVERecord?id=CVE-2024-52798',
                    ],
                    PublishedDate: '2024-12-05T23:15:06.31Z',
                    LastModifiedDate: '2025-01-24T20:15:33.107Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-45296',
                    PkgID: 'path-to-regexp@1.8.0',
                    PkgName: 'path-to-regexp',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/path-to-regexp@1.8.0',
                        UID: 'acf7d9c4b595f02',
                    },
                    InstalledVersion: '1.8.0',
                    FixedVersion: '1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-45296',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'path-to-regexp: Backtracking regular expressions cause ReDoS',
                    Description:
                        'path-to-regexp turns path strings into a regular expressions. In certain cases, path-to-regexp will output a regular expression that can be exploited to cause poor performance. Because JavaScript is single threaded and regex matching runs on the main thread, poor performance will block the event loop and lead to a DoS. The bad regular expression is generated any time you have two parameters within a single segment, separated by something that is not a period (.). For users of 0.1, upgrade to 0.1.10. All other users should upgrade to 8.0.0.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        'cbl-mariner': 3,
                        ghsa: 3,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
                            V3Score: 5.3,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-45296',
                        'https://github.com/pillarjs/path-to-regexp',
                        'https://github.com/pillarjs/path-to-regexp/commit/29b96b4a1de52824e1ca0f49a701183cc4ed476f',
                        'https://github.com/pillarjs/path-to-regexp/commit/60f2121e9b66b7b622cc01080df0aabda9eedee6',
                        'https://github.com/pillarjs/path-to-regexp/commit/925ac8e3c5780b02f58cbd4e52f95da8ad2ac485',
                        'https://github.com/pillarjs/path-to-regexp/commit/d31670ae8f6e69cbfd56e835742195b7d10942ef',
                        'https://github.com/pillarjs/path-to-regexp/commit/f1253b47b347dcb909e3e80b0eb2649109e59894',
                        'https://github.com/pillarjs/path-to-regexp/releases/tag/v6.3.0',
                        'https://github.com/pillarjs/path-to-regexp/security/advisories/GHSA-9wv6-86v2-598j',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-45296',
                        'https://security.netapp.com/advisory/ntap-20250124-0001',
                        'https://security.netapp.com/advisory/ntap-20250124-0001/',
                        'https://www.cve.org/CVERecord?id=CVE-2024-45296',
                    ],
                    PublishedDate: '2024-09-09T19:15:13.33Z',
                    LastModifiedDate: '2025-01-24T20:15:32.68Z',
                },
                {
                    VulnerabilityID: 'CVE-2023-44270',
                    PkgID: 'postcss@7.0.39',
                    PkgName: 'postcss',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/postcss@7.0.39',
                        UID: '2f6f457f87e74a1a',
                    },
                    InstalledVersion: '7.0.39',
                    FixedVersion: '8.4.31',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-44270',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'PostCSS: Improper input validation in PostCSS',
                    Description:
                        'An issue was discovered in PostCSS before 8.4.31. The vulnerability affects linters using PostCSS to parse external untrusted CSS. An attacker can prepare CSS in such a way that it will contains parts parsed by PostCSS as a CSS comment. After processing by PostCSS, it will be included in the PostCSS output in CSS nodes (rules, properties) despite being included in a comment.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-74'],
                    VendorSeverity: {
                        ghsa: 2,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
                            V3Score: 5.3,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
                            V3Score: 5.3,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N',
                            V3Score: 5.3,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2023-44270',
                        'https://github.com/github/advisory-database/issues/2820',
                        'https://github.com/postcss/postcss',
                        'https://github.com/postcss/postcss/blob/main/lib/tokenize.js#L25',
                        'https://github.com/postcss/postcss/commit/58cc860b4c1707510c9cd1bc1fa30b423a9ad6c5',
                        'https://github.com/postcss/postcss/releases/tag/8.4.31',
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-44270',
                        'https://www.cve.org/CVERecord?id=CVE-2023-44270',
                    ],
                    PublishedDate: '2023-09-29T22:15:11.867Z',
                    LastModifiedDate: '2024-11-21T08:25:33.443Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-47068',
                    PkgID: 'rollup@2.79.1',
                    PkgName: 'rollup',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/rollup@2.79.1',
                        UID: '4354d554816302fc',
                    },
                    InstalledVersion: '2.79.1',
                    FixedVersion: '3.29.5, 4.22.4, 2.79.2',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-47068',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'rollup: DOM Clobbering Gadget found in rollup bundled scripts that leads to XSS',
                    Description:
                        'Rollup is a module bundler for JavaScript. Versions prior to 2.79.2, 3.29.5, and 4.22.4 are susceptible to a DOM Clobbering vulnerability when bundling scripts with properties from `import.meta` (e.g., `import.meta.url`) in `cjs`/`umd`/`iife` format. The DOM Clobbering gadget can lead to cross-site scripting (XSS) in web pages where scriptless attacker-controlled HTML elements (e.g., an `img` tag with an unsanitized `name` attribute) are present. Versions 2.79.2, 3.29.5, and 4.22.4  contain a patch for the vulnerability.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 3,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H',
                            V3Score: 6.4,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H',
                            V3Score: 6.4,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-47068',
                        'https://github.com/rollup/rollup',
                        'https://github.com/rollup/rollup/blob/b86ffd776cfa906573d36c3f019316d02445d9ef/src/ast/nodes/MetaProperty.ts#L157-L162',
                        'https://github.com/rollup/rollup/blob/b86ffd776cfa906573d36c3f019316d02445d9ef/src/ast/nodes/MetaProperty.ts#L180-L185',
                        'https://github.com/rollup/rollup/commit/2ef77c00ec2635d42697cff2c0567ccc8db34fb4',
                        'https://github.com/rollup/rollup/commit/e2552c9e955e0a61f70f508200ee9f752f85a541',
                        'https://github.com/rollup/rollup/security/advisories/GHSA-gcx4-mw62-g8wm',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-47068',
                        'https://www.cve.org/CVERecord?id=CVE-2024-47068',
                    ],
                    PublishedDate: '2024-09-23T16:15:06.947Z',
                    LastModifiedDate: '2024-10-29T16:15:05.583Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-43799',
                    PkgID: 'send@0.18.0',
                    PkgName: 'send',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/send@0.18.0',
                        UID: 'c9a6f2eb3b15a61d',
                    },
                    InstalledVersion: '0.18.0',
                    FixedVersion: '0.19.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-43799',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'send: Code Execution Vulnerability in Send Library',
                    Description:
                        'Send is a library for streaming files from the file system as a http response. Send passes untrusted user input to SendStream.redirect() which executes untrusted code. This issue is patched in send 0.19.0.',
                    Severity: 'LOW',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        'cbl-mariner': 2,
                        ghsa: 1,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L',
                            V3Score: 5,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 4.7,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L',
                            V3Score: 5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-43799',
                        'https://github.com/pillarjs/send',
                        'https://github.com/pillarjs/send/commit/ae4f2989491b392ae2ef3b0015a019770ae65d35',
                        'https://github.com/pillarjs/send/security/advisories/GHSA-m6fv-jmcg-4jfg',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-43799',
                        'https://www.cve.org/CVERecord?id=CVE-2024-43799',
                    ],
                    PublishedDate: '2024-09-10T15:15:17.727Z',
                    LastModifiedDate: '2024-09-20T16:57:14.687Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-11831',
                    PkgID: 'serialize-javascript@6.0.1',
                    PkgName: 'serialize-javascript',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/serialize-javascript@6.0.1',
                        UID: '3910822ada3438e',
                    },
                    InstalledVersion: '6.0.1',
                    FixedVersion: '6.0.2',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-11831',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'npm-serialize-javascript: Cross-site Scripting (XSS) in serialize-javascript',
                    Description:
                        'A flaw was found in npm-serialize-javascript. The vulnerability occurs because the serialize-javascript module does not properly sanitize certain inputs, such as regex or other JavaScript object types, allowing an attacker to inject malicious code. This code could be executed when deserialized by a web browser, causing Cross-site scripting (XSS) attacks. This issue is critical in environments where serialized data is sent to web clients, potentially compromising the security of the website or web application using this package.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 5.4,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 5.4,
                        },
                    },
                    References: [
                        'https://access.redhat.com/errata/RHBA-2025:0304',
                        'https://access.redhat.com/errata/RHSA-2025:1334',
                        'https://access.redhat.com/errata/RHSA-2025:1468',
                        'https://access.redhat.com/errata/RHSA-2025:4511',
                        'https://access.redhat.com/security/cve/CVE-2024-11831',
                        'https://bugzilla.redhat.com/show_bug.cgi?id=2312579',
                        'https://github.com/yahoo/serialize-javascript',
                        'https://github.com/yahoo/serialize-javascript/commit/7f3ac252d86b802454cb43782820aea2e0f6dc25',
                        'https://github.com/yahoo/serialize-javascript/commit/f27d65d3de42affe2aac14607066c293891cec4e',
                        'https://github.com/yahoo/serialize-javascript/pull/173',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-11831',
                        'https://www.cve.org/CVERecord?id=CVE-2024-11831',
                    ],
                    PublishedDate: '2025-02-10T16:15:37.08Z',
                    LastModifiedDate: '2025-05-06T08:15:15.8Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-43800',
                    PkgID: 'serve-static@1.15.0',
                    PkgName: 'serve-static',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/serve-static@1.15.0',
                        UID: 'df2cb580ce17b0ba',
                    },
                    InstalledVersion: '1.15.0',
                    FixedVersion: '1.16.0, 2.1.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-43800',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'serve-static: Improper Sanitization in serve-static',
                    Description:
                        'serve-static serves static files. serve-static passes untrusted user input - even after sanitizing it - to redirect() may execute untrusted code. This issue is patched in serve-static 1.16.0.',
                    Severity: 'LOW',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        'cbl-mariner': 2,
                        ghsa: 1,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L',
                            V3Score: 5,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 4.7,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L',
                            V3Score: 5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-43800',
                        'https://github.com/expressjs/serve-static',
                        'https://github.com/expressjs/serve-static/commit/0c11fad159898cdc69fd9ab63269b72468ecaf6b',
                        'https://github.com/expressjs/serve-static/commit/ce730896fddce1588111d9ef6fdf20896de5c6fa',
                        'https://github.com/expressjs/serve-static/security/advisories/GHSA-cm22-4g7w-348p',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-43800',
                        'https://www.cve.org/CVERecord?id=CVE-2024-43800',
                    ],
                    PublishedDate: '2024-09-10T15:15:17.937Z',
                    LastModifiedDate: '2024-09-20T17:36:30.313Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-12905',
                    PkgID: 'tar-fs@2.1.1',
                    PkgName: 'tar-fs',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tar-fs@2.1.1',
                        UID: '1a9a2e80008ccc31',
                    },
                    InstalledVersion: '2.1.1',
                    FixedVersion: '1.16.4, 2.1.2, 3.0.8',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-12905',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'tar-fs: link following and path traversal via maliciously crafted tar file',
                    Description:
                        'An Improper Link Resolution Before File Access ("Link Following") and Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal"). This vulnerability occurs when extracting a maliciously crafted tar file, which can result in unauthorized file writes or overwrites outside the intended extraction directory. The issue is associated with index.js in the tar-fs package.\n\nThis issue affects tar-fs: from 0.0.0 before 1.16.4, from 2.0.0 before 2.1.2, from 3.0.0 before 3.0.8.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-22', 'CWE-59'],
                    VendorSeverity: {
                        'cbl-mariner': 3,
                        ghsa: 3,
                        redhat: 3,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
                            V3Score: 7.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
                            V3Score: 7.5,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-12905',
                        'https://github.com/mafintosh/tar-fs',
                        'https://github.com/mafintosh/tar-fs/commit/a1dd7e7c7f4b4a8bd2ab60f513baca573b44e2ed',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-12905',
                        'https://www.cve.org/CVERecord?id=CVE-2024-12905',
                        'https://www.seal.security/blog/a-link-to-the-past-uncovering-a-new-vulnerability-in-tar-fs',
                    ],
                    PublishedDate: '2025-03-27T17:15:53.25Z',
                    LastModifiedDate: '2025-04-20T16:15:13.913Z',
                },
                {
                    VulnerabilityID: 'CVE-2023-45818',
                    PkgID: 'tinymce@6.6.2',
                    PkgName: 'tinymce',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tinymce@6.6.2',
                        UID: 'afe1a0f7e05caea3',
                    },
                    InstalledVersion: '6.6.2',
                    FixedVersion: '6.7.1, 5.10.8',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-45818',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'TinyMCE is an open source rich text editor. A mutation cross-site scri ...',
                    Description:
                        "TinyMCE is an open source rich text editor. A mutation cross-site scripting (mXSS) vulnerability was discovered in TinyMCE’s core undo and redo functionality. When a carefully-crafted HTML snippet passes the XSS sanitisation layer, it is manipulated as a string by internal trimming functions before being stored in the undo stack. If the HTML snippet is restored from the undo stack, the combination of the string manipulation and reparative parsing by either the browser's native [DOMParser API](https://developer.mozilla.org/en-US/docs/Web/API/DOMParser) (TinyMCE 6) or the SaxParser API (TinyMCE 5) mutates the HTML maliciously, allowing an XSS payload to be executed. This vulnerability has been patched in TinyMCE 5.10.8 and TinyMCE 6.7.1 by ensuring HTML is trimmed using node-level manipulation instead of string manipulation. Users are advised to upgrade. There are no known workarounds for this vulnerability.",
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                        nvd: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://github.com/tinymce/tinymce',
                        'https://github.com/tinymce/tinymce/security/advisories/GHSA-v65r-p3vv-jjfv',
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-45818',
                        'https://researchgate.net/publication/266654651_mXSS_attacks_Attacking_well-secured_web-applications_by_using_innerHTML_mutations',
                        'https://tiny.cloud/docs/release-notes/release-notes5108/#securityfixes',
                        'https://tiny.cloud/docs/tinymce/6/6.7.1-release-notes/#security-fixes',
                        'https://www.tiny.cloud/docs/api/tinymce.html/tinymce.html.saxparser',
                        'https://www.tiny.cloud/docs/api/tinymce.html/tinymce.html.saxparser/',
                    ],
                    PublishedDate: '2023-10-19T22:15:10.817Z',
                    LastModifiedDate: '2024-11-21T08:27:25.077Z',
                },
                {
                    VulnerabilityID: 'CVE-2023-45819',
                    PkgID: 'tinymce@6.6.2',
                    PkgName: 'tinymce',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tinymce@6.6.2',
                        UID: 'afe1a0f7e05caea3',
                    },
                    InstalledVersion: '6.6.2',
                    FixedVersion: '6.7.1, 5.10.8',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-45819',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'TinyMCE is an open source rich text editor. A cross-site scripting (XS ...',
                    Description:
                        "TinyMCE is an open source rich text editor. A cross-site scripting (XSS) vulnerability was discovered in TinyMCE’s Notification Manager API. The vulnerability exploits TinyMCE's unfiltered notification system, which is used in error handling. The conditions for this exploit requires carefully crafted malicious content to have been inserted into the editor and a notification to have been triggered. When a notification was opened, the HTML within the text argument was displayed unfiltered in the notification. The vulnerability allowed arbitrary JavaScript execution when an notification presented in the TinyMCE UI for the current user.  This issue could also be exploited by any integration which uses a TinyMCE notification to display unfiltered HTML content. This vulnerability has been patched in TinyMCE 5.10.8 and TinyMCE 6.7.1 by ensuring that the HTML displayed in the notification is sanitized, preventing the exploit. Users are advised to upgrade. There are no known workarounds for this vulnerability.\n",
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                        nvd: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://github.com/tinymce/tinymce',
                        'https://github.com/tinymce/tinymce/security/advisories/GHSA-hgqx-r2hp-jr38',
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-45819',
                        'https://tiny.cloud/docs/release-notes/release-notes5108/#securityfixes',
                        'https://tiny.cloud/docs/tinymce/6/6.7.1-release-notes/#security-fixes',
                    ],
                    PublishedDate: '2023-10-19T22:15:11.15Z',
                    LastModifiedDate: '2024-11-21T08:27:25.233Z',
                },
                {
                    VulnerabilityID: 'CVE-2023-48219',
                    PkgID: 'tinymce@6.6.2',
                    PkgName: 'tinymce',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tinymce@6.6.2',
                        UID: 'afe1a0f7e05caea3',
                    },
                    InstalledVersion: '6.6.2',
                    FixedVersion: '5.10.9, 6.7.3',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-48219',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'TinyMCE is an open source rich text editor. A mutation cross-site scri ...',
                    Description:
                        'TinyMCE is an open source rich text editor. A mutation cross-site scripting (mXSS) vulnerability was discovered in TinyMCE’s core undo/redo functionality and other APIs and plugins. Text nodes within specific parents are not escaped upon serialization according to the HTML standard. If such text nodes contain a special character reserved as an internal marker, they can be combined with other HTML patterns to form malicious snippets. These snippets pass the initial sanitisation layer when the content is parsed into the editor body, but can trigger XSS when the special internal marker is removed from the content and re-parsed. his vulnerability has been patched in TinyMCE versions 6.7.3 and 5.10.9. Users are advised to upgrade. There are no known workarounds for this vulnerability.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                        nvd: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://github.com/tinymce/tinymce',
                        'https://github.com/tinymce/tinymce/releases/tag/5.10.9',
                        'https://github.com/tinymce/tinymce/releases/tag/6.7.3',
                        'https://github.com/tinymce/tinymce/security/advisories/GHSA-v626-r774-j7f8',
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-48219',
                        'https://tiny.cloud/docs/release-notes/release-notes5109',
                        'https://tiny.cloud/docs/release-notes/release-notes5109/',
                        'https://tiny.cloud/docs/tinymce/6/6.7.3-release-notes',
                        'https://tiny.cloud/docs/tinymce/6/6.7.3-release-notes/',
                    ],
                    PublishedDate: '2023-11-15T19:15:07.857Z',
                    LastModifiedDate: '2024-11-21T08:31:14.003Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-29203',
                    PkgID: 'tinymce@6.6.2',
                    PkgName: 'tinymce',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tinymce@6.6.2',
                        UID: 'afe1a0f7e05caea3',
                    },
                    InstalledVersion: '6.6.2',
                    FixedVersion: '6.8.1',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-29203',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'TinyMCE is an open source rich text editor. Across-site scripting (XSS ...',
                    Description:
                        'TinyMCE is an open source rich text editor. A cross-site scripting (XSS) vulnerability was discovered in TinyMCE’s content insertion code.  This allowed `iframe` elements containing malicious code to execute when inserted into the editor.  These `iframe` elements are restricted in their permissions by same-origin browser protections, but could still trigger operations such as downloading of malicious assets. This vulnerability is fixed in 6.8.1.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
                            V3Score: 4.3,
                        },
                    },
                    References: [
                        'https://github.com/tinymce/tinymce',
                        'https://github.com/tinymce/tinymce/commit/bcdea2ad14e3c2cea40743fb48c63bba067ae6d1',
                        'https://github.com/tinymce/tinymce/security/advisories/GHSA-438c-3975-5x3f',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-29203',
                        'https://www.tiny.cloud/docs/tinymce/6/6.8.1-release-notes/#new-convert_unsafe_embeds-option-that-controls-whether-object-and-embed-elements-will-be-converted-to-more-restrictive-alternatives-namely-img-for-image-mime-types-video-for-video-mime-types-audio-audio-mime-types-or-iframe-for-other-or-unspecified-mime-types',
                        'https://www.tiny.cloud/docs/tinymce/7/7.0-release-notes/#sandbox_iframes-editor-option-is-now-defaulted-to-true',
                    ],
                    PublishedDate: '2024-03-26T14:15:08.747Z',
                    LastModifiedDate: '2024-11-21T09:07:48.683Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-29881',
                    PkgID: 'tinymce@6.6.2',
                    PkgName: 'tinymce',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tinymce@6.6.2',
                        UID: 'afe1a0f7e05caea3',
                    },
                    InstalledVersion: '6.6.2',
                    FixedVersion: '7.0.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-29881',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'TinyMCE is an open source rich text editor.  A cross-site scripting (X ...',
                    Description:
                        'TinyMCE is an open source rich text editor.  A cross-site scripting (XSS) vulnerability was discovered in TinyMCE’s content loading and content inserting code. A SVG image could be loaded though an `object` or `embed` element and that image could potentially contain a XSS payload. This vulnerability is fixed in 6.8.1 and 7.0.0.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N',
                            V3Score: 4.3,
                        },
                    },
                    References: [
                        'https://github.com/tinymce/tinymce',
                        'https://github.com/tinymce/tinymce/commit/bcdea2ad14e3c2cea40743fb48c63bba067ae6d1',
                        'https://github.com/tinymce/tinymce/security/advisories/GHSA-5359-pvf2-pw78',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-29881',
                        'https://www.tiny.cloud/docs/tinymce/6/6.8.1-release-notes/#new-convert_unsafe_embeds-option-that-controls-whether-object-and-embed-elements-will-be-converted-to-more-restrictive-alternatives-namely-img-for-image-mime-types-video-for-video-mime-types-audio-audio-mime-types-or-iframe-for-other-or-unspecified-mime-types',
                        'https://www.tiny.cloud/docs/tinymce/7/7.0-release-notes/#convert_unsafe_embeds-editor-option-is-now-defaulted-to-true',
                    ],
                    PublishedDate: '2024-03-26T14:15:09.07Z',
                    LastModifiedDate: '2024-11-21T09:08:32.393Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-38356',
                    PkgID: 'tinymce@6.6.2',
                    PkgName: 'tinymce',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tinymce@6.6.2',
                        UID: 'afe1a0f7e05caea3',
                    },
                    InstalledVersion: '6.6.2',
                    FixedVersion: '5.11.0, 6.8.4, 7.2.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-38356',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'TinyMCE is an open source rich text editor. A cross-site scripting (XS ...',
                    Description:
                        'TinyMCE is an open source rich text editor. A cross-site scripting (XSS) vulnerability was discovered in TinyMCE’s content extraction code. When using the `noneditable_regexp` option, specially crafted HTML attributes containing malicious code were able to be executed when content was extracted from the editor. This vulnerability has been patched in TinyMCE 7.2.0, TinyMCE 6.8.4 and TinyMCE 5.11.0 LTS by ensuring that, when using the `noneditable_regexp` option, any content within an attribute is properly verified to match the configured regular expression before being added. Users are advised to upgrade. There are no known workarounds for this vulnerability.\n',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://github.com/tinymce/tinymce',
                        'https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d',
                        'https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0',
                        'https://github.com/tinymce/tinymce/security/advisories/GHSA-9hcv-j9pv-qmph',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-38356',
                        'https://owasp.org/www-community/attacks/xss',
                        'https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview',
                        'https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview',
                        'https://www.tiny.cloud/docs/tinymce/latest/7.2-release-notes/#overview',
                    ],
                    PublishedDate: '2024-06-19T20:15:11.453Z',
                    LastModifiedDate: '2024-11-21T09:25:26.203Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-38357',
                    PkgID: 'tinymce@6.6.2',
                    PkgName: 'tinymce',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/tinymce@6.6.2',
                        UID: 'afe1a0f7e05caea3',
                    },
                    InstalledVersion: '6.6.2',
                    FixedVersion: '5.11.0, 6.8.4, 7.2.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-38357',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'TinyMCE is an open source rich text editor. A cross-site scripting (XS ...',
                    Description:
                        'TinyMCE is an open source rich text editor. A cross-site scripting (XSS) vulnerability was discovered in TinyMCE’s content parsing code. This allowed specially crafted noscript elements containing malicious code to be executed when that content was loaded into the editor. This vulnerability has been patched in TinyMCE 7.2.0, TinyMCE 6.8.4 and TinyMCE 5.11.0 LTS by ensuring that content within noscript elements are properly parsed. Users are advised to upgrade. There are no known workarounds for this vulnerability.\n',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        ghsa: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://github.com/tinymce/tinymce',
                        'https://github.com/tinymce/tinymce/commit/5acb741665a98e83d62b91713c800abbff43b00d',
                        'https://github.com/tinymce/tinymce/commit/a9fb858509f86dacfa8b01cfd34653b408983ac0',
                        'https://github.com/tinymce/tinymce/security/advisories/GHSA-w9jx-4g6g-rp7x',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-38357',
                        'https://owasp.org/www-community/attacks/xss',
                        'https://www.tiny.cloud/docs/tinymce/6/6.8.4-release-notes/#overview',
                        'https://www.tiny.cloud/docs/tinymce/7/7.2-release-notes/#overview',
                    ],
                    PublishedDate: '2024-06-19T20:15:11.727Z',
                    LastModifiedDate: '2024-11-21T09:25:26.463Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-43788',
                    PkgID: 'webpack@5.78.0',
                    PkgName: 'webpack',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/webpack@5.78.0',
                        UID: '5a695dd7bc4831af',
                    },
                    InstalledVersion: '5.78.0',
                    FixedVersion: '5.94.0',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-43788',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'webpack: DOM Clobbering vulnerability in AutoPublicPathRuntimeModule',
                    Description:
                        'Webpack is a module bundler. Its main purpose is to bundle JavaScript files for usage in a browser, yet it is also capable of transforming, bundling, or packaging just about any resource or asset. The webpack developers have discovered a DOM Clobbering vulnerability in Webpack’s `AutoPublicPathRuntimeModule`. The DOM Clobbering gadget in the module can lead to cross-site scripting (XSS) in web pages where scriptless attacker-controlled HTML elements (e.g., an `img` tag with an unsanitized `name` attribute) are present. Real-world exploitation of this gadget has been observed in the Canvas LMS which allows a XSS attack to happen through a javascript code compiled by Webpack (the vulnerable part is from Webpack). DOM Clobbering is a type of code-reuse attack where the attacker first embeds a piece of non-script, seemingly benign HTML markups in the webpage (e.g. through a post or comment) and leverages the gadgets (pieces of js code) living in the existing javascript code to transform it into executable code. This vulnerability can lead to cross-site scripting (XSS) on websites that include Webpack-generated files and allow users to inject certain scriptless HTML tags with improperly sanitized name or id attributes. This issue has been addressed in release version 5.94.0. All users are advised to upgrade. There are no known workarounds for this issue.',
                    Severity: 'MEDIUM',
                    CweIDs: ['CWE-79'],
                    VendorSeverity: {
                        azure: 2,
                        ghsa: 2,
                        nvd: 2,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H',
                            V3Score: 6.4,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                            V3Score: 6.1,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-43788',
                        'https://github.com/webpack/webpack',
                        'https://github.com/webpack/webpack/commit/955e057abc6cc83cbc3fa1e1ef67a49758bf5a61',
                        'https://github.com/webpack/webpack/issues/18718#issuecomment-2326296270',
                        'https://github.com/webpack/webpack/security/advisories/GHSA-4vvj-4cpr-p986',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-43788',
                        'https://research.securitum.com/xss-in-amp4email-dom-clobbering',
                        'https://scnps.co/papers/sp23_domclob.pdf',
                        'https://www.cve.org/CVERecord?id=CVE-2024-43788',
                    ],
                    PublishedDate: '2024-08-27T17:15:07.967Z',
                    LastModifiedDate: '2024-09-03T15:15:15.937Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-37890',
                    PkgID: 'ws@8.13.0',
                    PkgName: 'ws',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/ws@8.13.0',
                        UID: '6f3222fc3013563d',
                    },
                    InstalledVersion: '8.13.0',
                    FixedVersion: '5.2.4, 6.2.3, 7.5.10, 8.17.1',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-37890',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'nodejs-ws: denial of service when handling a request with many HTTP headers',
                    Description:
                        'ws is an open source WebSocket client and server for Node.js. A request with a number of headers exceeding theserver.maxHeadersCount threshold could be used to crash a ws server. The vulnerability was fixed in ws@8.17.1 (e55e510) and backported to ws@7.5.10 (22c2876), ws@6.2.3 (eeb76d3), and ws@5.2.4 (4abd8f6). In vulnerable versions of ws, the issue can be mitigated in the following ways: 1. Reduce the maximum allowed length of the request headers using the --max-http-header-size=size and/or the maxHeaderSize options so that no more headers than the server.maxHeadersCount limit can be sent. 2. Set server.maxHeadersCount to 0 so that no limit is applied.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-476'],
                    VendorSeverity: {
                        'cbl-mariner': 3,
                        ghsa: 3,
                        redhat: 2,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                        redhat: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 5.9,
                        },
                    },
                    References: [
                        'https://access.redhat.com/security/cve/CVE-2024-37890',
                        'https://github.com/websockets/ws',
                        'https://github.com/websockets/ws/commit/22c28763234aa75a7e1b76f5c01c181260d7917f',
                        'https://github.com/websockets/ws/commit/4abd8f6de4b0b65ef80b3ff081989479ed93377e',
                        'https://github.com/websockets/ws/commit/e55e5106f10fcbaac37cfa89759e4cc0d073a52c',
                        'https://github.com/websockets/ws/commit/eeb76d313e2a00dd5247ca3597bba7877d064a63',
                        'https://github.com/websockets/ws/issues/2230',
                        'https://github.com/websockets/ws/pull/2231',
                        'https://github.com/websockets/ws/security/advisories/GHSA-3h5v-q93c-6h6q',
                        'https://nodejs.org/api/http.html#servermaxheaderscount',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-37890',
                        'https://www.cve.org/CVERecord?id=CVE-2024-37890',
                    ],
                    PublishedDate: '2024-06-17T20:15:13.203Z',
                    LastModifiedDate: '2024-11-21T09:24:28.81Z',
                },
                {
                    VulnerabilityID: 'CVE-2023-30533',
                    PkgID: 'xlsx@0.18.5',
                    PkgName: 'xlsx',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/xlsx@0.18.5',
                        UID: 'c5c4d78405336188',
                    },
                    InstalledVersion: '0.18.5',
                    FixedVersion: '0.19.3',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2023-30533',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'Prototype Pollution in sheetJS',
                    Description:
                        'SheetJS Community Edition before 0.19.3 allows Prototype Pollution via a crafted file. In other words. 0.19.2 and earlier are affected, whereas 0.19.3 and later are unaffected.',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-1321'],
                    VendorSeverity: {
                        ghsa: 3,
                        nvd: 3,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
                            V3Score: 7.8,
                        },
                        nvd: {
                            V3Vector:
                                'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
                            V3Score: 7.8,
                        },
                    },
                    References: [
                        'https://cdn.sheetjs.com/advisories/CVE-2023-30533',
                        'https://git.sheetjs.com/sheetjs/sheetjs',
                        'https://git.sheetjs.com/sheetjs/sheetjs/issues/2667',
                        'https://git.sheetjs.com/sheetjs/sheetjs/issues/2986',
                        'https://git.sheetjs.com/sheetjs/sheetjs/src/branch/master/CHANGELOG.md',
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-30533',
                    ],
                    PublishedDate: '2023-04-24T08:15:07.217Z',
                    LastModifiedDate: '2025-02-04T20:15:47.887Z',
                },
                {
                    VulnerabilityID: 'CVE-2024-22363',
                    PkgID: 'xlsx@0.18.5',
                    PkgName: 'xlsx',
                    PkgIdentifier: {
                        PURL: 'pkg:npm/xlsx@0.18.5',
                        UID: 'c5c4d78405336188',
                    },
                    InstalledVersion: '0.18.5',
                    FixedVersion: '0.20.2',
                    Status: 'fixed',
                    Layer: {},
                    SeveritySource: 'ghsa',
                    PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-22363',
                    DataSource: {
                        ID: 'ghsa',
                        Name: 'GitHub Security Advisory npm',
                        URL: 'https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm',
                    },
                    Title: 'SheetJS Regular Expression Denial of Service (ReDoS)',
                    Description:
                        'SheetJS Community Edition before 0.20.2 is vulnerable.to Regular Expression Denial of Service (ReDoS).',
                    Severity: 'HIGH',
                    CweIDs: ['CWE-1333'],
                    VendorSeverity: {
                        ghsa: 3,
                    },
                    CVSS: {
                        ghsa: {
                            V3Vector:
                                'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
                            V3Score: 7.5,
                        },
                    },
                    References: [
                        'https://cdn.sheetjs.com/advisories/CVE-2024-22363',
                        'https://cwe.mitre.org/data/definitions/1333.html',
                        'https://git.sheetjs.com/sheetjs/sheetjs',
                        'https://git.sheetjs.com/sheetjs/sheetjs/src/tag/v0.20.2',
                        'https://nvd.nist.gov/vuln/detail/CVE-2024-22363',
                    ],
                    PublishedDate: '2024-04-05T06:15:10.2Z',
                    LastModifiedDate: '2024-11-21T08:56:07.53Z',
                },
            ],
        },
    ],
};

export default function VulnerabilityList() {
    const [expandedIndex, setExpandedIndex] = useState(null);
    const [filterSeverity, setFilterSeverity] = useState('ALL');

    const results = jsonData.Results[0]?.Vulnerabilities || [];

    const filteredResults =
        filterSeverity === 'ALL'
            ? results
            : results.filter((vuln) => vuln.Severity === filterSeverity);

    const toggleExpand = (index) => {
        setExpandedIndex(expandedIndex === index ? null : index);
    };

    const getSeverityColor = (severity) => {
        switch (severity) {
            case 'CRITICAL':
                return '#7B1FA2'; // deep purple
            case 'HIGH':
                return '#D32F2F'; // red
            case 'MEDIUM':
                return '#FF9800'; // orange
            case 'LOW':
                return '#4CAF50'; // green
            default:
                return '#9E9E9E'; // grey
        }
    };

    return (
        <Container maxWidth="lg" sx={{ my: 5 }}>
            <Box
                sx={{
                    textAlign: 'center',
                    mb: 5,
                    p: 4,
                    borderRadius: 2,
                    boxShadow: '0 4px 20px rgba(0,0,0,0.08)',
                    background:
                        'linear-gradient(145deg, #ffffff 0%, #f5f7fa 100%)',
                }}
            >
                <Typography
                    variant="h3"
                    gutterBottom
                    sx={{
                        fontWeight: 600,
                        color: '#1a237e',
                        mb: 2,
                    }}
                >
                    Vulnerability Report
                </Typography>
                <Typography
                    variant="subtitle1"
                    color="text.secondary"
                    sx={{ mb: 3, fontSize: '1.1rem' }}
                >
                    Scanned at: {new Date(jsonData.CreatedAt).toLocaleString()}
                </Typography>

                <Box
                    sx={{
                        display: 'flex',
                        justifyContent: 'center',
                        gap: 2,
                        mb: 2,
                    }}
                >
                    {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(
                        (severity) => (
                            <Chip
                                key={severity}
                                label={severity}
                                onClick={() => setFilterSeverity(severity)}
                                sx={{
                                    px: 2,
                                    fontWeight: 'bold',
                                    backgroundColor:
                                        filterSeverity === severity
                                            ? severity === 'ALL'
                                                ? '#1976d2'
                                                : getSeverityColor(severity)
                                            : 'rgba(0,0,0,0.08)',
                                    color:
                                        filterSeverity === severity
                                            ? 'white'
                                            : 'text.primary',
                                    '&:hover': {
                                        backgroundColor:
                                            filterSeverity === severity
                                                ? severity === 'ALL'
                                                    ? '#1565c0'
                                                    : getSeverityColor(severity)
                                                : 'rgba(0,0,0,0.12)',
                                    },
                                }}
                            />
                        )
                    )}
                </Box>

                <Typography variant="body2" color="text.secondary">
                    Showing {filteredResults.length} of {results.length}{' '}
                    vulnerabilities
                </Typography>
            </Box>

            {filteredResults.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 8 }}>
                    <Typography variant="h6" color="text.secondary">
                        No vulnerabilities match the selected filter
                    </Typography>
                </Box>
            ) : (
                filteredResults.map((vuln, idx) => (
                    <Card
                        key={vuln.VulnerabilityID}
                        variant="outlined"
                        sx={{
                            mb: 3,
                            borderRadius: 2,
                            borderLeft: `6px solid ${getSeverityColor(
                                vuln.Severity
                            )}`,
                            transition: 'transform 0.2s, box-shadow 0.2s',
                            '&:hover': {
                                boxShadow: '0 5px 15px rgba(0,0,0,0.1)',
                                transform: 'translateY(-2px)',
                            },
                        }}
                    >
                        <CardContent>
                            <Box
                                display="flex"
                                justifyContent="space-between"
                                alignItems="flex-start"
                                flexWrap="wrap"
                                gap={1}
                            >
                                <Box>
                                    <Typography
                                        variant="h6"
                                        sx={{ fontWeight: 'bold', mb: 0.5 }}
                                    >
                                        {vuln.PkgName}{' '}
                                        <span
                                            style={{ color: 'text.secondary' }}
                                        >
                                            ({vuln.InstalledVersion})
                                        </span>
                                    </Typography>
                                    <Typography
                                        variant="caption"
                                        color="text.secondary"
                                        sx={{
                                            display: 'inline-block',
                                            backgroundColor: 'rgba(0,0,0,0.04)',
                                            px: 1,
                                            py: 0.5,
                                            borderRadius: 1,
                                        }}
                                    >
                                        {vuln.VulnerabilityID}
                                    </Typography>
                                </Box>
                                <Chip
                                    label={vuln.Severity}
                                    sx={{
                                        backgroundColor: getSeverityColor(
                                            vuln.Severity
                                        ),
                                        color: 'white',
                                        fontWeight: 'bold',
                                        px: 1,
                                    }}
                                />
                            </Box>
                            <Typography
                                variant="subtitle1"
                                sx={{
                                    mt: 2,
                                    fontWeight: 'medium',
                                    lineHeight: 1.4,
                                }}
                            >
                                {vuln.Title}
                            </Typography>
                            <Box
                                sx={{
                                    mt: 2,
                                    display: 'flex',
                                    flexWrap: 'wrap',
                                    gap: 2,
                                    alignItems: 'center',
                                }}
                            >
                                <Chip
                                    label={`Status: ${vuln.Status}`}
                                    size="small"
                                    color={
                                        vuln.Status === 'fixed'
                                            ? 'success'
                                            : 'default'
                                    }
                                />
                                <Chip
                                    label={`Fixed in: ${vuln.FixedVersion}`}
                                    size="small"
                                    variant="outlined"
                                />
                                <Typography
                                    variant="body2"
                                    color="text.secondary"
                                >
                                    Published:{' '}
                                    {new Date(
                                        vuln.PublishedDate
                                    ).toLocaleDateString()}
                                </Typography>
                            </Box>
                        </CardContent>

                        <CardActions sx={{ px: 2, pb: 2 }}>
                            <Button
                                variant={
                                    expandedIndex === idx
                                        ? 'contained'
                                        : 'outlined'
                                }
                                size="small"
                                onClick={() => toggleExpand(idx)}
                                startIcon={
                                    expandedIndex === idx ? (
                                        <ExpandLessIcon />
                                    ) : (
                                        <ExpandMoreIcon />
                                    )
                                }
                                sx={{ mr: 2 }}
                                color="primary"
                            >
                                {expandedIndex === idx
                                    ? 'Hide Details'
                                    : 'Show Details'}
                            </Button>
                            <Button
                                size="small"
                                variant="outlined"
                                component={Link}
                                href={vuln.PrimaryURL}
                                target="_blank"
                                rel="noopener"
                            >
                                View Advisory
                            </Button>
                        </CardActions>

                        <Collapse
                            in={expandedIndex === idx}
                            timeout="auto"
                            unmountOnExit
                        >
                            <CardContent
                                sx={{
                                    pt: 0,
                                    backgroundColor: 'rgba(0,0,0,0.02)',
                                }}
                            >
                                <Typography
                                    variant="body1"
                                    paragraph
                                    sx={{ lineHeight: 1.6 }}
                                >
                                    {vuln.Description}
                                </Typography>

                                {vuln.CweIDs && vuln.CweIDs.length > 0 && (
                                    <Box sx={{ mb: 3 }}>
                                        <Typography
                                            variant="subtitle2"
                                            gutterBottom
                                            sx={{ fontWeight: 'bold' }}
                                        >
                                            CWE IDs:
                                        </Typography>
                                        <Box
                                            sx={{
                                                display: 'flex',
                                                gap: 1,
                                                flexWrap: 'wrap',
                                            }}
                                        >
                                            {vuln.CweIDs.map((cwe) => (
                                                <Chip
                                                    key={cwe}
                                                    label={cwe}
                                                    size="small"
                                                    color="secondary"
                                                    variant="outlined"
                                                />
                                            ))}
                                        </Box>
                                    </Box>
                                )}

                                <Typography
                                    variant="subtitle2"
                                    gutterBottom
                                    sx={{ fontWeight: 'bold' }}
                                >
                                    References:
                                </Typography>
                                <Box
                                    sx={{
                                        maxHeight: '200px',
                                        overflow: 'auto',
                                        borderRadius: 1,
                                        border: '1px solid rgba(0,0,0,0.1)',
                                        p: 1,
                                    }}
                                >
                                    {vuln.References.map((ref, i) => (
                                        <Box
                                            key={i}
                                            sx={{
                                                py: 1,
                                                borderBottom:
                                                    i <
                                                    vuln.References.length - 1
                                                        ? '1px solid rgba(0,0,0,0.06)'
                                                        : 'none',
                                            }}
                                        >
                                            <Link
                                                href={ref}
                                                target="_blank"
                                                rel="noopener"
                                                sx={{ wordBreak: 'break-all' }}
                                            >
                                                {ref}
                                            </Link>
                                        </Box>
                                    ))}
                                </Box>
                            </CardContent>
                        </Collapse>
                    </Card>
                ))
            )}
        </Container>
    );
}
