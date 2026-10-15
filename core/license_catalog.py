from __future__ import annotations

import re


UNKNOWN_LICENSE_VALUES = {
    "",
    "unknown",
    "none",
    "null",
    "not_found",
    "n/a",
}


HIGH_RISK_LICENSES = {
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "SSPL-1.0",
    "BUSL-1.1",
    "Commons-Clause",
}


MEDIUM_RISK_LICENSES = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EPL-2.0",
    "CDDL-1.0",
    "EPL-1.0",
    "CDDL-1.1",
}


LOW_RISK_LICENSES = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
    "Unlicense",
    "CC0-1.0",
    "Python-2.0",
    "HPND",
    "WTFPL",
    "CC-BY-4.0",
    # Observed on real npm inventories (minimatch 10.2.6 declared
    # BlueOak-1.0.0; json-schema 0.4.0 declared AFL-2.1 inside an OR
    # expression).  Both are OSI-approved permissive licences; leaving them
    # out of the catalogue while the report's category column called the same
    # rows "Permissive" was the 654-vs-646 audit inconsistency.
    "BlueOak-1.0.0",
    "AFL-2.1",
    # MIT No Attribution (@csstools/color-helpers) -- permissive, and the
    # only licence that explicitly waives the attribution NOTICE set exists
    # to track, so it deliberately does not join NOTICE_REQUIRED_LICENSES.
    "MIT-0",
}


NOTICE_REQUIRED_LICENSES = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MPL-2.0",
    "EPL-2.0",
    "Python-2.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "EPL-1.0",
    "CDDL-1.1",
    "CC-BY-4.0",
    "HPND",
    "AFL-2.1",
}


LICENSE_ALIASES = {
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "mit license": "MIT",
    "bsd": "BSD-3-Clause",
    "gplv3": "GPL-3.0",
    "gpl3": "GPL-3.0",
    "agplv3": "AGPL-3.0",
    "lgplv3": "LGPL-3.0",

    # ------------------------------------------------------------------------
    # Long-form and legacy spellings, added from a measurement of the prodtest
    # corpus rather than from a spec.
    #
    # Before these, `normalize_license` returned the input unchanged for anything
    # it did not recognise, and the caller then recorded
    # license_resolution_status = RESOLVED_FROM_CANONICAL_REPORT. So a PyPI
    # classifier string was published as a resolved licence with an authoritative
    # sounding status. That is worse than an unknown: an unknown row is honestly
    # marked as a gap and somebody goes and fixes it, whereas a confidently wrong
    # licence is quoted into a compliance answer.
    #
    # Measured across 23 corpus artifacts, these exact strings were being reported
    # as resolved while not being SPDX identifiers:
    #     "GNU General Public License, version 2"        49 components -> GPL-2.0-only
    #     "AGPLv3 License"                                 49 -> AGPL-3.0-or-later
    #     "GNU General Public License, version 2 (GPL2)"  44 -> GPL-2.0-only
    #     "MIT/X11"                                         4 -> MIT
    #
    # "-only" rather than "-or-later" for GPL-2.0 because the long form states
    # version 2 with no "or later" qualifier; choosing -or-later would be a
    # licence-compliance decision this scan has no basis to make. -only is the
    # faithful reading, and it is the stricter of the two for a redistributor.
    # ------------------------------------------------------------------------
    "gnu general public license, version 2": "GPL-2.0-only",
    "gnu general public license, version 2 (gpl2)": "GPL-2.0-only",
    "gnu general public license v2.0": "GPL-2.0-only",
    "gpl2": "GPL-2.0-only",
    "gnu general public license, version 3": "GPL-3.0-only",
    "gnu affero general public license, version 3": "AGPL-3.0-only",
    "agplv3 license": "AGPL-3.0-only",
    "agpl3": "AGPL-3.0-only",
    "lesser general public license, version 2.1": "LGPL-2.1-only",
    "lesser general public license, version 3": "LGPL-3.0-only",
    "lgpl2.1": "LGPL-2.1-only",
    # Legacy X11 spelling of MIT, still shipped by several packages.
    "mit/x11": "MIT",
    "mit/x11 variant": "MIT",
    "the mit license": "MIT",
    "expat": "MIT",
    "expat license": "MIT",
    "bsd-3": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "isc license": "ISC",
}

# A declared licence that is a POINTER to a file rather than an identifier.
# SPDX defines "LicenseRef-..." for this; these must never be reported as resolved
# identifiers, because "SEE LICENSE IN COPYING.txt" answers none of the questions
# a compliance reader asks about a dependency -- whether it is permitted, whether
# it needs a notice, whether it is copyleft. Measured: 3 components across the
# corpus (2 x COPYING.txt, 1 x README.md).
LICENSE_FILE_POINTER_RE = re.compile(
    r"^see\s+licen[sc]e\s+in\s+\S+", re.IGNORECASE)


def is_license_file_pointer(value: str | None) -> bool:
    """True when the declared value points at a file instead of naming a licence."""
    if not value:
        return False
    return bool(LICENSE_FILE_POINTER_RE.match(str(value).strip()))


KNOWN_PACKAGE_LICENSES = {
    # Python
    "flask": "BSD-3-Clause",
    "jinja2": "BSD-3-Clause",
    "werkzeug": "BSD-3-Clause",
    "requests": "Apache-2.0",
    "urllib3": "MIT",
    "certifi": "MPL-2.0",
    "django": "BSD-3-Clause",
    "pyyaml": "MIT",
    "sqlalchemy": "MIT",
    "cryptography": "Apache-2.0",
    "pillow": "HPND",
    "paramiko": "LGPL-2.1",

    # JavaScript / npm common
    "lodash": "MIT",
    "axios": "MIT",
    "express": "MIT",
    "moment": "MIT",
    "node-fetch": "MIT",
    "react": "MIT",
    "react-dom": "MIT",
    "typescript": "Apache-2.0",
    "webpack": "MIT",
    "eslint": "MIT",
    "babel": "MIT",
    "postcss": "MIT",
    "autoprefixer": "MIT",
    "browserslist": "MIT",
    "chalk": "MIT",
    "commander": "MIT",
    "debug": "MIT",
    "dotenv": "BSD-2-Clause",
    "glob": "ISC",
    "graceful-fs": "ISC",
    "json5": "MIT",
    "mime": "MIT",
    "minimatch": "ISC",
    "prop-types": "MIT",
    "resolve": "MIT",
    "semver": "ISC",
    "source-map": "BSD-3-Clause",
    "yargs": "MIT",
    "abab": "BSD-3-Clause",
    "accepts": "MIT",
    "acorn": "MIT",
    "ajv": "MIT",
    "ansi-regex": "MIT",
    "ansi-styles": "MIT",
    "anymatch": "ISC",
    "argparse": "Python-2.0",
    "async": "MIT",
    "axe-core": "MPL-2.0",
    "body-parser": "MIT",
    "braces": "MIT",

    # Java
    "log4j": "Apache-2.0",
    "spring": "Apache-2.0",
        # More common npm packages
    "acorn-globals": "MIT",
    "acorn-jsx": "MIT",
    "acorn-walk": "MIT",
    "agent-base": "MIT",
    "aggregate-error": "MIT",
    "ansi-escapes": "MIT",
    "aria-query": "Apache-2.0",
    "array-flatten": "MIT",
    "array-includes": "MIT",
    "array-union": "MIT",
    "asap": "MIT",
    "asynckit": "MIT",
    "atob": "MIT",
    "balanced-match": "MIT",
    "base64-js": "MIT",
    "binary-extensions": "MIT",
    "brace-expansion": "MIT",
    "buffer": "MIT",
    "bytes": "MIT",
    "callsites": "MIT",
    "camelcase": "MIT",
    "caniuse-lite": "CC-BY-4.0",
    "chokidar": "MIT",
    "clean-stack": "MIT",
    "cliui": "ISC",
    "color-convert": "MIT",
    "color-name": "MIT",
    "combined-stream": "MIT",
    "concat-map": "MIT",
    "convert-source-map": "MIT",
    "cookie": "MIT",
    "core-js": "MIT",
    "cross-spawn": "MIT",
    "css-loader": "MIT",
    "css-select": "BSD-2-Clause",
    "css-what": "BSD-2-Clause",
    "cssesc": "MIT",
    "csstype": "MIT",
    "decode-uri-component": "MIT",
    "deep-is": "MIT",
    "delayed-stream": "MIT",
    "detect-newline": "MIT",
    "dom-accessibility-api": "MIT",
    "electron-to-chromium": "ISC",
    "emoji-regex": "MIT",
    "entities": "BSD-2-Clause",
    "error-ex": "MIT",
    "escape-string-regexp": "MIT",
    "escodegen": "BSD-2-Clause",
    "eslint-scope": "BSD-2-Clause",
    "eslint-visitor-keys": "Apache-2.0",
    "espree": "BSD-2-Clause",
    "esprima": "BSD-2-Clause",
    "estraverse": "BSD-2-Clause",
    "esutils": "BSD-2-Clause",
    "fast-deep-equal": "MIT",
    "fast-glob": "MIT",
    "fast-json-stable-stringify": "MIT",
    "fast-levenshtein": "MIT",
    "fastq": "ISC",
    "file-entry-cache": "MIT",
    "fill-range": "MIT",
    "find-up": "MIT",
    "flat-cache": "MIT",
    "flatted": "ISC",
    "follow-redirects": "MIT",
    "form-data": "MIT",
    "fs-extra": "MIT",
    "gensync": "MIT",
    "get-caller-file": "ISC",
    "get-intrinsic": "MIT",
    "get-stream": "MIT",
    "globals": "MIT",
    "has": "MIT",
    "has-flag": "MIT",
    "html-entities": "MIT",
    "htmlparser2": "MIT",
    "http-proxy": "MIT",
    "ignore": "MIT",
    "import-fresh": "MIT",
    "imurmurhash": "MIT",
    "inherits": "ISC",
    "is-arrayish": "MIT",
    "is-binary-path": "MIT",
    "is-core-module": "MIT",
    "is-extglob": "MIT",
    "is-fullwidth-code-point": "MIT",
    "is-glob": "MIT",
    "is-number": "MIT",
    "is-plain-obj": "MIT",
    "is-stream": "MIT",
    "isarray": "MIT",
    "isexe": "ISC",
    "jest": "MIT",
    "jest-worker": "MIT",
    "js-tokens": "MIT",
    "js-yaml": "MIT",
    "jsesc": "MIT",
    "json-buffer": "MIT",
    "json-parse-even-better-errors": "MIT",
    "json-schema-traverse": "MIT",
    "json-stable-stringify-without-jsonify": "MIT",
    "kind-of": "MIT",
    "kleur": "MIT",
    "leven": "MIT",
    "levn": "MIT",
    "loader-utils": "MIT",
    "locate-path": "MIT",
    "loose-envify": "MIT",
    "lru-cache": "ISC",
    "make-dir": "MIT",
    "merge2": "MIT",
    "micromatch": "MIT",
    "ms": "MIT",
    "natural-compare": "MIT",
    "neo-async": "MIT",
    "node-releases": "MIT",
    "normalize-path": "MIT",
    "object-assign": "MIT",
    "once": "ISC",
    "optionator": "MIT",
    "p-limit": "MIT",
    "p-locate": "MIT",
    "p-try": "MIT",
    "parse-json": "MIT",
    "path-exists": "MIT",
    "path-is-absolute": "MIT",
    "path-key": "MIT",
    "path-parse": "MIT",
    "picocolors": "ISC",
    "picomatch": "MIT",
    "pkg-dir": "MIT",
    "prelude-ls": "MIT",
    "pretty-format": "MIT",
    "process": "MIT",
    "punycode": "MIT",
    "queue-microtask": "MIT",
    "react-is": "MIT",
    "readable-stream": "MIT",
    "readdirp": "MIT",
    "regenerator-runtime": "MIT",
    "require-directory": "MIT",
    "resolve-from": "MIT",
    "reusify": "MIT",
    "rimraf": "ISC",
    "run-parallel": "MIT",
    "safe-buffer": "MIT",
    "scheduler": "MIT",
    "schema-utils": "MIT",
    "shebang-command": "MIT",
    "shebang-regex": "MIT",
    "signal-exit": "ISC",
    "slash": "MIT",
    "source-map-js": "BSD-3-Clause",
    "sprintf-js": "BSD-3-Clause",
    "string-width": "MIT",
    "string_decoder": "MIT",
    "strip-ansi": "MIT",
    "strip-bom": "MIT",
    "strip-json-comments": "MIT",
    "supports-color": "MIT",
    "supports-preserve-symlinks-flag": "MIT",
    "tapable": "MIT",
    "terser": "BSD-2-Clause",
    "to-regex-range": "MIT",
    "tslib": "0BSD",
    "type-check": "MIT",
    "universalify": "MIT",
    "uri-js": "BSD-2-Clause",
    "util-deprecate": "MIT",
    "walker": "Apache-2.0",
    "which": "ISC",
    "word-wrap": "MIT",
    "wrap-ansi": "MIT",
    "wrappy": "ISC",
    "y18n": "ISC",
    "yallist": "ISC",
    "yargs-parser": "ISC",
    "babel-jest": "MIT",
    "babel-loader": "MIT",
    "babel-plugin-istanbul": "BSD-3-Clause",
    "babel-preset-jest": "MIT",
    "babel-preset-react-app": "MIT",
    "basic-auth": "MIT",
    "big.js": "MIT",
    "bluebird": "MIT",
    "boolbase": "ISC",
    "buffer-from": "MIT",
    "ci-info": "MIT",
    "clean-css": "MIT",
    "clsx": "MIT",
    "co": "MIT",
    "compression": "MIT",
    "content-type": "MIT",
    "cookie-signature": "MIT",
    "core-js-compat": "MIT",
    "core-js-pure": "MIT",
    "cssnano": "MIT",
    "cssnano-preset-default": "MIT",
    "decimal.js": "MIT",
    "deep-equal": "MIT",
    "deepmerge": "MIT",
    "depd": "MIT",
    "destroy": "MIT",
    "dom-serializer": "MIT",
    "domhandler": "BSD-2-Clause",
    "domutils": "BSD-2-Clause",
    "ejs": "Apache-2.0",
    "enhanced-resolve": "MIT",
    "eslint-plugin-import": "MIT",
    "eslint-plugin-jest": "MIT",
    "eslint-plugin-react": "MIT",
    "eslint-plugin-react-hooks": "MIT",
    "etag": "MIT",
    "eventemitter3": "MIT",
    "execa": "MIT",
    "expect": "MIT",
    "file-loader": "MIT",
    "finalhandler": "MIT",
    "fresh": "MIT",
    "glob-parent": "ISC",
    "globby": "MIT",
    "got": "MIT",
    "he": "MIT",
    "html-webpack-plugin": "MIT",
    "http-errors": "MIT",
    "http-proxy-agent": "MIT",
    "https-proxy-agent": "MIT",
    "iconv-lite": "MIT",
    "immer": "MIT",
    "inflight": "ISC",
    "ini": "ISC",
    "ip": "MIT",
    "ipaddr.js": "MIT",
    "istanbul-lib-coverage": "BSD-3-Clause",
    "istanbul-lib-instrument": "BSD-3-Clause",
    "istanbul-lib-report": "BSD-3-Clause",
    "istanbul-lib-source-maps": "BSD-3-Clause",
    "istanbul-reports": "BSD-3-Clause",
    "jest-cli": "MIT",
    "jest-config": "MIT",
    "jest-diff": "MIT",
    "jest-environment-jsdom": "MIT",
    "jest-environment-node": "MIT",
    "jest-mock": "MIT",
    "jest-resolve": "MIT",
    "jest-runtime": "MIT",
    "jest-snapshot": "MIT",
    "jest-util": "MIT",
    "jsdom": "MIT",
    "jsonfile": "MIT",
    "keyv": "MIT",
    "left-pad": "WTFPL",
    "lodash.debounce": "MIT",
    "lodash.memoize": "MIT",
    "lodash.merge": "MIT",
    "lodash.sortby": "MIT",
    "lodash.uniq": "MIT",
    "mime-db": "MIT",
    "mime-types": "MIT",
    "minimist": "MIT",
    "mkdirp": "MIT",
    "morgan": "MIT",
    "nanoid": "MIT",
    "negotiator": "MIT",
    "node-forge": "BSD-3-Clause",
    "normalize-url": "MIT",
    "nth-check": "BSD-2-Clause",
    "openai": "Apache-2.0",
    "parse5": "MIT",
    "parseurl": "MIT",
    "path-to-regexp": "MIT",
    "postcss-loader": "MIT",
    "postcss-selector-parser": "MIT",
    "postcss-value-parser": "MIT",
    "prompts": "MIT",
    "proxy-addr": "MIT",
    "qs": "BSD-3-Clause",
    "range-parser": "MIT",
    "raw-body": "MIT",
    "react-dev-utils": "MIT",
    "react-refresh": "MIT",
    "react-scripts": "MIT",
    "react-transition-group": "BSD-3-Clause",
    "regenerator-transform": "MIT",
    "rollup": "MIT",
    "sass-loader": "MIT",
    "send": "MIT",
    "serve-index": "MIT",
    "serve-static": "MIT",
    "sockjs": "MIT",
    "stack-utils": "MIT",
    "statuses": "MIT",
    "style-loader": "MIT",
    "stylis": "MIT",
    "svgo": "MIT",
    "tailwindcss": "MIT",
    "terser-webpack-plugin": "MIT",
    "tough-cookie": "BSD-3-Clause",
    "uuid": "MIT",
    "vary": "MIT",
    "webpack-dev-server": "MIT",
    "webpack-sources": "MIT",
    "whatwg-fetch": "MIT",
    "ws": "MIT",
    "yaml": "ISC",
    
    "com.fasterxml.jackson.core:jackson-databind": "Apache-2.0",
    "com.jolbox:bonecp": "Apache-2.0",
    "commons-dbcp:commons-dbcp": "Apache-2.0",
    "commons-fileupload:commons-fileupload": "Apache-2.0",
    "commons-pool:commons-pool": "Apache-2.0",
    "javax.servlet:javax.servlet-api": "CDDL-1.1",
    "javax.servlet.jsp:javax.servlet.jsp-api": "CDDL-1.1",
    "javax.validation:validation-api": "Apache-2.0",
    "javax.xml.bind:jaxb-api": "CDDL-1.1",
    "junit:junit": "EPL-1.0",
    "log4j:log4j": "Apache-2.0",
    "mysql:mysql-connector-java": "GPL-2.0",
    "org.apache.httpcomponents:httpclient": "Apache-2.0",
    "org.apache.logging.log4j:log4j-core": "Apache-2.0",
    "org.apache.logging.log4j:log4j-slf4j-impl": "Apache-2.0",
    "org.hibernate:hibernate-validator": "Apache-2.0",
    "org.hsqldb:hsqldb": "BSD-3-Clause",
    "org.postgresql:postgresql": "BSD-2-Clause",
    "org.springframework:spring-web": "Apache-2.0",
    "org.springframework:spring-webmvc": "Apache-2.0",
    "org.springframework:spring-jdbc": "Apache-2.0",
    "org.springframework:spring-test": "Apache-2.0",
    "org.springframework.security:spring-security-core": "Apache-2.0",
    "org.springframework.security:spring-security-config": "Apache-2.0",
    "org.springframework.security:spring-security-web": "Apache-2.0",
    "javax.servlet:jstl": "CDDL-1.1",
    "anthropic": "MIT",
    "cohere": "MIT",
    "google-generativeai": "Apache-2.0",
    "langchain": "MIT",
    "mistralai": "Apache-2.0",
    "ollama": "MIT",
    "pycryptodome": "BSD-2-Clause",
    "scikit-learn": "BSD-3-Clause",
    "sqlparse": "BSD-3-Clause",
    "tensorflow": "Apache-2.0",
    "torch": "BSD-3-Clause",
    "transformers": "Apache-2.0",
    "xgboost": "Apache-2.0",
    
     'acorn-import-assertions': 'MIT',
    'acorn-node': 'Apache-2.0',
    'address': 'MIT',
    'adjust-sourcemap-loader': 'MIT',
    'ajv-formats': 'MIT',
    'ajv-keywords': 'MIT',
    'ansi-html-community': 'Apache-2.0',
    'arg': 'MIT',
    'array.prototype.flat': 'MIT',
    'array.prototype.flatmap': 'MIT',
    'ast-types-flow': 'MIT',
    'at-least-node': 'MIT',
    'axobject-query': 'Apache-2.0',
    'batch': 'MIT',
    'bfj': 'MIT',
    'bonjour': 'MIT',
    'browser-process-hrtime': 'BSD-2-Clause',
    'bser': 'Apache-2.0',
    'buffer-indexof': 'MIT',
    'builtin-modules': 'MIT',
    'cacheable-lookup': 'MIT',
    'cacheable-request': 'MIT',
    'call-bind': 'MIT',
    'camel-case': 'MIT',
    'camelcase-css': 'MIT',
    'caniuse-api': 'MIT',
    'case-sensitive-paths-webpack-plugin': 'MIT',
    'char-regex': 'MIT',
    'charcodes': 'MIT',
    'check-types': 'MIT',
    'chrome-trace-event': 'MIT',
    'cjs-module-lexer': 'MIT',
    'clone-response': 'MIT',
    'coa': 'MIT',
    'collect-v8-coverage': 'MIT',
    'colord': 'MIT',
    'colorette': 'MIT',
    'common-path-prefix': 'ISC',
    'common-tags': 'MIT',
    'commondir': 'MIT',
    'compress-brotli': 'MIT',
    'compressible': 'MIT',
    'confusing-browser-globals': 'MIT',
    'connect-history-api-fallback': 'MIT',
    'content-disposition': 'MIT',
    'core-util-is': 'MIT',
    'cosmiconfig': 'MIT',
    'crypto-random-string': 'MIT',
    'css': 'MIT',
    'css-blank-pseudo': 'CC0-1.0',
    'css-declaration-sorter': 'ISC',
    'css-has-pseudo': 'CC0-1.0',
    'css-minimizer-webpack-plugin': 'MIT',
    'css-prefers-color-scheme': 'CC0-1.0',
    'css-select-base-adapter': 'MIT',
    'css-tree': 'MIT',
    'css.escape': 'MIT',
    'cssdb': 'CC0-1.0',
    'csso': 'MIT',
    'cssom': 'MIT',
    'cssstyle': 'MIT',
    'damerau-levenshtein': 'BSD-2-Clause',
    'data-urls': 'MIT',
    'decompress-response': 'MIT',
    'dedent': 'MIT',
    'default-gateway': 'BSD-2-Clause',
    'defer-to-connect': 'MIT',
    'define-lazy-prop': 'MIT',
    'define-properties': 'MIT',
    'defined': 'MIT',
    'del': 'MIT',
    'detect-node': 'MIT',
    'detect-port-alt': 'MIT',
    'detective': 'MIT',
    'didyoumean': 'MIT',
    'diff-sequences': 'MIT',
    'dir-glob': 'MIT',
    'dlv': 'MIT',
    'dns-equal': 'MIT',
    'dns-packet': 'MIT',
    'dns-txt': 'MIT',
    'doctrine': 'Apache-2.0',
    'dom-converter': 'MIT',
    'dom-helpers': 'BSD-3-Clause',
    'domelementtype': 'BSD-2-Clause',
    'domexception': 'MIT',
    'dot-case': 'MIT',
    'dotenv-expand': 'BSD-2-Clause',
    'duplexer': 'MIT',
    'ee-first': 'MIT',
    'emittery': 'MIT',
    'emojis-list': 'MIT',
    'encodeurl': 'MIT',
    'end-of-stream': 'MIT',
    'error-stack-parser': 'MIT',
    'es-abstract': 'MIT',
    'es-module-lexer': 'MIT',
    'es-to-primitive': 'MIT',
    'es6-promise': 'MIT',
    'escalade': 'MIT',
    'escape-html': 'MIT',
    'eslint-import-resolver-node': 'MIT',
    'eslint-module-utils': 'MIT',
    'eslint-utils': 'MIT',
    'eslint-webpack-plugin': 'MIT',
    'esquery': 'BSD-3-Clause',
    'esrecurse': 'BSD-2-Clause',
    'estree-walker': 'MIT',
    'events': 'MIT',
    'exit': 'MIT',
    'express-http-proxy': 'MIT',
    'faye-websocket': 'Apache-2.0',
    'fb-watchman': 'Apache-2.0',
    'filelist': 'Apache-2.0',
    'filesize': 'BSD-3-Clause',
    'find-cache-dir': 'MIT',
    'find-root': 'MIT',
    'fork-ts-checker-webpack-plugin': 'MIT',
    'forwarded': 'MIT',
    'fraction.js': 'MIT',
    'fs-monkey': 'Unlicense',
    'fs.realpath': 'ISC',
    'fsevents': 'MIT',
    'function-bind': 'MIT',
    'functional-red-black-tree': 'MIT',
    'get-own-enumerable-property-symbols': 'ISC',
    'get-package-type': 'MIT',
    'get-symbol-description': 'MIT',
    'glob-to-regexp': 'BSD-2-Clause',
    'global-modules': 'MIT',
    'global-prefix': 'MIT',
    'gzip-size': 'MIT',
    'hamt_plus': 'MIT',
    'handle-thing': 'MIT',
    'harmony-reflect': 'MIT',
    'has-bigints': 'MIT',
    'has-symbols': 'MIT',
    'has-tostringtag': 'MIT',
    'hoist-non-react-statics': 'BSD-3-Clause',
    'hoopy': 'ISC',
    'hpack.js': 'MIT',
    'html-encoding-sniffer': 'MIT',
    'html-escaper': 'MIT',
    'html-minifier-terser': 'MIT',
    'http-cache-semantics': 'BSD-2-Clause',
    'http-deceiver': 'MIT',
    'http-parser-js': 'MIT',
    'http-proxy-middleware': 'MIT',
    'http2-wrapper': 'MIT',
    'human-signals': 'Apache-2.0',
    'icss-utils': 'ISC',
    'idb': 'ISC',
    'identity-obj-proxy': 'MIT',
    'import-local': 'MIT',
    'indent-string': 'MIT',
    'internal-slot': 'MIT',
    'is-arguments': 'MIT',
    'is-bigint': 'MIT',
    'is-boolean-object': 'MIT',
    'is-callable': 'MIT',
    'is-date-object': 'MIT',
    'is-docker': 'MIT',
    'is-generator-fn': 'MIT',
    'is-module': 'MIT',
    'is-negative-zero': 'MIT',
    'is-number-object': 'MIT',
    'is-obj': 'MIT',
    'is-path-cwd': 'MIT',
    'is-path-inside': 'MIT',
    'is-potential-custom-element-name': 'MIT',
    'is-regex': 'MIT',
    'is-regexp': 'MIT',
    'is-root': 'MIT',
    'is-shared-array-buffer': 'MIT',
    'is-string': 'MIT',
    'is-symbol': 'MIT',
    'is-typedarray': 'MIT',
    'is-weakref': 'MIT',
    'is-wsl': 'MIT',
    'jake': 'Apache-2.0',
    'json-parse-better-errors': 'MIT',
    'json-schema': 'AFL-2.1',
    'jsonpointer': 'MIT',
    'jsx-ast-utils': 'MIT',
    'klona': 'MIT',
    'language-subtag-registry': 'ODC-By-1.0',
    'language-tags': 'MIT',
    'lilconfig': 'MIT',
    'lines-and-columns': 'MIT',
    'loader-runner': 'MIT',
    'lower-case': 'MIT',
    'lowercase-keys': 'MIT',
    'lz-string': 'MIT',
    'magic-string': 'MIT',
    'makeerror': 'BSD-3-Clause',
    'mdn-data': 'CC0-1.0',
    'media-typer': 'MIT',
    'memfs': 'Unlicense',
    'merge-descriptors': 'MIT',
    'merge-stream': 'MIT',
    'methods': 'MIT',
    'mimic-fn': 'MIT',
    'mimic-response': 'MIT',
    'min-indent': 'MIT',
    'mini-css-extract-plugin': 'MIT',
    'minimalistic-assert': 'ISC',
    'multicast-dns': 'MIT',
    'multicast-dns-service-types': 'MIT',
    'no-case': 'MIT',
    'node-int64': 'MIT',
    'normalize-range': 'MIT',
    'npm-run-path': 'MIT',
    'nwsapi': 'MIT',
    'object-hash': 'MIT',
    'object-inspect': 'MIT',
    'object-is': 'MIT',
    'object-keys': 'MIT',
    'object.assign': 'MIT',
    'object.entries': 'MIT',
    'object.fromentries': 'MIT',
    'object.getownpropertydescriptors': 'MIT',
    'object.hasown': 'MIT',
    'object.values': 'MIT',
    'obuf': 'MIT',
    'on-finished': 'MIT',
    'on-headers': 'MIT',
    'onetime': 'MIT',
    'open': 'MIT',
    'p-cancelable': 'MIT',
    'p-map': 'MIT',
    'p-retry': 'MIT',
    'param-case': 'MIT',
    'parent-module': 'MIT',
    'pascal-case': 'MIT',
    'path-type': 'MIT',
    'performance-now': 'MIT',
    'pirates': 'MIT',
    'pkg-up': 'MIT',
    'portfinder': 'MIT',
    'pretty-bytes': 'MIT',
    'pretty-error': 'MIT',
    'process-nextick-args': 'MIT',
    'promise': 'MIT',
    'psl': 'MIT',
    'pump': 'MIT',
    'q': 'MIT',
    'quick-lru': 'MIT',
    'raf': 'MIT',
    'randombytes': 'MIT',
    'recoil': 'MIT',
    'recursive-readdir': 'MIT',
    'redent': 'MIT',
    'regenerate': 'MIT',
    'regenerate-unicode-properties': 'MIT',
    'regex-parser': 'MIT',
    'regexp.prototype.flags': 'MIT',
    'regexpp': 'MIT',
    'regexpu-core': 'MIT',
    'regjsgen': 'MIT',
    'regjsparser': 'BSD-2-Clause',
    'relateurl': 'MIT',
    'renderkid': 'MIT',
    'require-from-string': 'MIT',
    'requires-port': 'MIT',
    'resolve-alpn': 'MIT',
    'resolve-cwd': 'MIT',
    'resolve-url-loader': 'MIT',
    'resolve.exports': 'MIT',
    'responselike': 'MIT',
    'retry': 'MIT',
    'rollup-plugin-terser': 'MIT',
    'safer-buffer': 'MIT',
    'sanitize.css': 'CC0-1.0',
    'sax': 'ISC',
    'saxes': 'ISC',
    'select-hose': 'MIT',
    'selfsigned': 'MIT',
    'serialize-javascript': 'BSD-3-Clause',
    'setprototypeof': 'ISC',
    'shell-quote': 'MIT',
    'side-channel': 'MIT',
    'sisteransi': 'MIT',
    'source-list-map': 'MIT',
    'source-map-loader': 'MIT',
    'source-map-resolve': 'MIT',
    'source-map-support': 'MIT',
    'sourcemap-codec': 'MIT',
    'spdy': 'MIT',
    'spdy-transport': 'MIT',
    'stable': 'MIT',
    'stackframe': 'MIT',
    'string-length': 'MIT',
    'string-natural-compare': 'MIT',
    'string.prototype.matchall': 'MIT',
    'string.prototype.trimend': 'MIT',
    'string.prototype.trimstart': 'MIT',
    'stringify-object': 'MIT',
    'strip-comments': 'MIT',
    'strip-final-newline': 'MIT',
    'strip-indent': 'MIT',
    'stylehacks': 'MIT',
    'supports-hyperlinks': 'MIT',
    'svg-parser': 'MIT',
    'symbol-tree': 'MIT',
    'temp-dir': 'MIT',
    'tempy': 'MIT',
    'terminal-link': 'MIT',
    'test-exclude': 'ISC',
    'text-table': 'MIT',
    'throat': 'MIT',
    'thunky': 'MIT',
    'timsort': 'MIT',
    'tmpl': 'BSD-3-Clause',
    'to-fast-properties': 'MIT',
    'toidentifier': 'MIT',
    'tr46': 'MIT',
    'tryer': 'MIT',
    'tsconfig-paths': 'MIT',
    'tsutils': 'MIT',
    'type-detect': 'MIT',
    'type-fest': 'MIT',
    'type-is': 'MIT',
    'typedarray-to-buffer': 'MIT',
    'unbox-primitive': 'MIT',
    'unicode-canonical-property-names-ecmascript': 'MIT',
    'unicode-match-property-ecmascript': 'MIT',
    'unicode-match-property-value-ecmascript': 'MIT',
    'unicode-property-aliases-ecmascript': 'MIT',
    'unique-string': 'MIT',
    'unpipe': 'MIT',
    'unquote': 'MIT',
    'upath': 'MIT',
    'util.promisify': 'MIT',
    'utila': 'MIT',
    'utils-merge': 'MIT',
    'v8-compile-cache': 'MIT',
    'v8-to-istanbul': 'ISC',
    'w3c-hr-time': 'MIT',
    'w3c-xmlserializer': 'MIT',
    'watchpack': 'MIT',
    'wbuf': 'MIT',
    'web-vitals': 'MIT',
    'webidl-conversions': 'MIT',
    'websocket-driver': 'Apache-2.0',
    'websocket-extensions': 'Apache-2.0',
    'whatwg-encoding': 'MIT',
    'whatwg-mimetype': 'MIT',
    'whatwg-url': 'MIT',
    'which-boxed-primitive': 'MIT',
    'write-file-atomic': 'ISC',
    'xml-name-validator': 'MIT',
    'xmlchars': 'MIT',
    'xtend': 'MIT',
    'yocto-queue': 'MIT',

}


SCOPED_NPM_LICENSE_PREFIXES = {
    "@babel/": "MIT",
    "@types/": "MIT",
    "@mui/": "MIT",
    "@jest/": "MIT",
    "@typescript-eslint/": "MIT",
    "@emotion/": "MIT",
    "@svgr/": "MIT",
    "@testing-library/": "MIT",
    "@anthropic-ai/": "MIT",
    "@google/": "Apache-2.0",
    "@jridgewell/": "MIT",
    "@webassemblyjs/": "MIT",
    "@csstools/": "CC0-1.0",
    "@eslint/": "MIT",
    "@rollup/": "MIT",
    "@nodelib/": "MIT",
    "@popperjs/": "MIT",
    "@sinonjs/": "BSD-3-Clause",
    "@istanbuljs/": "BSD-3-Clause",
    "@humanwhocodes/": "Apache-2.0",
    "@rushstack/": "MIT",
    "@pmmmwh/": "MIT",
    "@surma/": "Apache-2.0",
    "@tootallnate/": "MIT",
    "@trysound/": "MIT",
    "@xtuc/": "MIT",
    "@ampproject/": "Apache-2.0",
    "@bcoe/": "MIT",
    "@langchain/": "MIT",
    "@sindresorhus/": "MIT",
    "@szmarczak/": "MIT",
    "@vercel/": "MIT",
}

PACKAGE_NAME_PREFIX_LICENSES = {
    "babel-plugin-": "MIT",
    "babel-preset-": "MIT",
    "jest-": "MIT",
    "eslint-plugin-": "MIT",
    "eslint-config-": "MIT",
    "postcss-": "MIT",
    "cssnano-": "MIT",
    "workbox-": "MIT",
    "webpack-": "MIT",
    "react-": "MIT",
    "lodash.": "MIT",
    "istanbul-": "BSD-3-Clause",
}

def normalize_license(value: str | None) -> str:
    if value is None:
        return "UNKNOWN"

    raw = str(value).strip()

    if raw.lower() in UNKNOWN_LICENSE_VALUES:
        return "UNKNOWN"

    # A pointer to a file is not a licence identifier. Returning it unchanged
    # published "SEE LICENSE IN COPYING.txt" as a resolved licence; returning it
    # as UNKNOWN would overstate, because the declaration exists and simply is not
    # an identifier. UNRESOLVED_FILE_REFERENCE says exactly that, and the evidence
    # column already carries the file.
    if is_license_file_pointer(raw):
        return "UNRESOLVED_FILE_REFERENCE"

    normalized = LICENSE_ALIASES.get(raw.lower())
    if normalized:
        return normalized

    # Long-form names carry a trailing qualifier in brackets or parentheses that the
    # alias table would miss, e.g. "GNU General Public License, version 2 (GPL2)".
    # Try the table again once with the trailing parenthetical removed, rather than
    # adding a combinatorial number of spellings to the table.
    stripped = re.sub(r"\s*[\(\[][^)\]]*[\)\]]\s*$", "", raw).strip()
    if stripped and stripped != raw:
        normalized = LICENSE_ALIASES.get(stripped.lower())
        if normalized:
            return normalized

    # Canonicalize known SPDX identifiers case-insensitively.
    for candidate in (HIGH_RISK_LICENSES | MEDIUM_RISK_LICENSES | LOW_RISK_LICENSES):
        if candidate.lower() == raw.lower():
            return candidate

    return raw


# ---------------------------------------------------------------------------
# Compound SPDX licence expressions
# ---------------------------------------------------------------------------
# Registry metadata publishes full SPDX expressions, not only single
# identifiers: "(MIT OR CC0-1.0)" (npm type-fest), "(AFL-2.1 OR
# BSD-3-Clause)" (json-schema), "(WTFPL OR MIT)" (opener).  Evaluate what the
# expression says instead of rejecting the whole string:
#
#   OR  -- the consumer may honour ANY one option, so the expression is
#          permissive only when every option is permissive.  A mixed
#          expression stays under review until the chosen option is
#          recorded: ALLOW would be guessing on the adopter's behalf.
#   AND -- every listed obligation applies, so the most restrictive part
#          governs the decision.
#
# Anything else (nested expressions, options the catalogue cannot classify)
# falls through to UNCLASSIFIED_LICENSE: an expression the parser cannot
# fully evaluate is exactly the one that needs a human.
_LICENSE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+\-]*")


def _split_license_expression(value: str) -> tuple[str, list[str]] | None:
    """Return (operator, tokens) for a single-level SPDX OR/AND expression.

    Handles both the parenthesised form registries prefer -- "(MIT OR
    CC0-1.0)" -- and the bare form package manifests and lockfiles carry --
    "MIT OR Apache-2.0", "Apache-2.0 AND LGPL-3.0-or-later".
    """
    inner = (
        value[1:-1].strip()
        if value.startswith("(") and value.endswith(")")
        else value.strip()
    )
    op_match = re.search(r"\s+(OR|AND)\s+", inner)
    if not op_match:
        return None
    tokens = [t.strip() for t in re.split(r"\s+(?:OR|AND)\s+", inner)]
    if len(tokens) < 2:
        return None
    if any(not _LICENSE_TOKEN_RE.fullmatch(t) for t in tokens):
        return None
    return op_match.group(1), tokens


def _risk_for_license_expression(value: str) -> tuple[str, str, str] | None:
    """Classify a compound expression; None means "fall through to review"."""
    split = _split_license_expression(value)
    if split is None:
        return None
    operator, tokens = split

    ids: list[str] = []
    for token in tokens:
        normalized = normalize_license(token)
        if normalized in {"UNKNOWN", "UNRESOLVED_FILE_REFERENCE"}:
            # An option we cannot classify: the expression cannot be
            # classified either.
            return None
        ids.append(normalized)

    if operator == "AND":
        order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

        def _governing(identifier: str) -> int:
            return order.get(license_risk(identifier)[0], 1)

        most_restrictive = max(ids, key=_governing)
        risk, issue, reason = license_risk(most_restrictive)
        return (
            risk,
            issue,
            f"{reason} Compound AND expression: the obligations of every "
            "listed licence apply.",
        )

    # OR
    if all(identifier in LOW_RISK_LICENSES for identifier in ids):
        return (
            "LOW",
            "PERMISSIVE_LICENSE",
            "Permissive licence expression (OR): every listed option is "
            "permissive and the consumer may honour any one of them; "
            "attribution obligations may still apply.",
        )

    if any(
        identifier in HIGH_RISK_LICENSES or identifier in MEDIUM_RISK_LICENSES
        for identifier in ids
    ):
        return (
            "MEDIUM",
            "MIXED_LICENSE_EXPRESSION",
            "Licence expression mixes permissive and non-permissive options "
            "(OR); record the consumer's choice before distribution.",
        )

    return None


def infer_package_license(package_name: str, current_license: str | None = None) -> str:
    current = normalize_license(current_license)

    if current != "UNKNOWN":
        return current

    raw = str(package_name or "").lower().strip()

    # scoped packages
    for prefix, license_id in SCOPED_NPM_LICENSE_PREFIXES.items():
        if raw.startswith(prefix):
            return license_id

    # normalize npm nested/scoped path
    key = raw.split("/")[-1]

    # broad family-prefix inference
    for prefix, license_id in PACKAGE_NAME_PREFIX_LICENSES.items():
        if key.startswith(prefix):
            return license_id

    # exact package mapping
    return KNOWN_PACKAGE_LICENSES.get(key, "UNKNOWN")
    

def license_risk(license_id: str) -> tuple[str, str, str]:
    normalized = normalize_license(license_id)

    if normalized == "UNKNOWN":
        return (
            "MEDIUM",
            "UNKNOWN_LICENSE",
            # "Legal review may be required" used to sit next to a summary
            # that reported legal_review_required = 0 and read as a
            # contradiction.  The routing is explicit: unknowns go to policy
            # review; legal escalation is the HIGH branch below.
            "License information is missing or unknown; policy review is "
            "required (legal review is reserved for strong-copyleft findings).",
        )

    if normalized in HIGH_RISK_LICENSES:
        return (
            "HIGH",
            "RESTRICTIVE_OR_STRONG_COPYLEFT",
            "Restrictive or strong copyleft license detected; proprietary distribution may require legal review.",
        )

    if normalized in MEDIUM_RISK_LICENSES:
        return (
            "MEDIUM",
            "COPYLEFT_OR_RECIPROCAL_LICENSE",
            "Copyleft or reciprocal license detected; compatibility and attribution obligations should be reviewed.",
        )

    if normalized in LOW_RISK_LICENSES:
        return (
            "LOW",
            "PERMISSIVE_LICENSE",
            "Permissive license detected; attribution obligations may still apply.",
        )

    # A compound SPDX expression is information, not an absence.  npm and
    # other registries publish "(MIT OR CC0-1.0)", "(AFL-2.1 OR
    # BSD-3-Clause)", "(WTFPL OR MIT)"; treating the whole expression as an
    # unrecognised string pushed genuinely permissive components into
    # UNCLASSIFIED_LICENSE / REVIEW_REQUIRED while the report's category
    # column -- set by the looser keyword pass -- called the same rows
    # Permissive, so the summary counted 654 permissive components and 131
    # review-required ones over overlapping sets.
    compound = _risk_for_license_expression(normalized)
    if compound is not None:
        return compound

    return (
        "MEDIUM",
        "UNCLASSIFIED_LICENSE",
        "License is not in the local policy catalog; review recommended.",
    )


def license_policy_decision(risk: str, issue: str) -> str:
    if risk == "HIGH":
        return "LEGAL_REVIEW_REQUIRED"

    if issue in {"UNKNOWN_LICENSE", "UNCLASSIFIED_LICENSE", "MIXED_LICENSE_EXPRESSION"}:
        return "REVIEW_REQUIRED"

    if risk == "MEDIUM":
        return "APPROVE_WITH_CONDITIONS"

    return "ALLOW"


def requires_notice(license_id: str) -> bool:
    normalized = normalize_license(license_id)
    # A compound expression carries the obligations of the options it names:
    # (MIT OR CC0-1.0) may be honoured as MIT, which requires notice.  Both
    # the parenthesised and the bare SPDX forms are recognised.
    if " OR " in normalized or " AND " in normalized:
        split = _split_license_expression(normalized)
        if split is not None:
            return any(requires_notice(token) for token in split[1])
    return normalized in NOTICE_REQUIRED_LICENSES
