"""Qualify the configured Mulder build and isolated MCP schemas; no case tools run."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lawliet_mobile.mulder_runtime import (PROFILES, RuntimeQualificationError,
    qualify_runtime, resolve_launcher, validate_tool_schemas)


async def schema_probe(launcher):
    # Optional dependencies are imported here so a missing runtime dependency is
    # reported without making LAWLIET's standard-library CLI depend on MCP.
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.types import PaginatedRequestParams
    from mulder.db import CaseDB
    launch = resolve_launcher(launcher)
    results = []
    with tempfile.TemporaryDirectory(prefix='lawliet-mcp-check-') as temporary:
        folder = Path(temporary)
        evidence = folder/'empty-synthetic-evidence'; evidence.mkdir()
        cases = folder/'synthetic-cases'
        # Restricted profiles require an existing parent. This empty temporary
        # database is solely protocol setup, never an existing customer case.
        database = CaseDB.create('RUNTIME_CHECK', str(evidence), cases)
        database.close()
        for profile in PROFILES:
            env = dict(launch['environment'], LAWLIET_MCP_PROFILE=profile,
                       PYTHONPYCACHEPREFIX=str(folder/'bytecode'/profile))
            params = StdioServerParameters(command=launch['launcher'],
                args=['serve', '--db-dir', str(cases), '--case-id', 'RUNTIME_CHECK', '--workers', '1'],
                env=env, cwd=str(folder))
            with tempfile.TemporaryFile(mode='w+') as error_log:
                async with stdio_client(params, errlog=error_log) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        schemas = {}; cursor = None; seen = set()
                        for page in range(20):
                            response = await session.list_tools(params=PaginatedRequestParams(cursor=cursor) if cursor else None)
                            for tool in response.tools:
                                wire = tool.model_dump(by_alias=True)
                                name = wire['name']
                                if name in schemas:
                                    raise RuntimeQualificationError('Duplicate MCP tool advertisement')
                                schemas[name] = wire.get('inputSchema', wire.get('input_schema', {}))
                                if len(schemas) > 1000:
                                    raise RuntimeQualificationError('MCP tool listing exceeds bound')
                            cursor = response.next_cursor
                            if not cursor: break
                            if cursor in seen: raise RuntimeQualificationError('Repeated MCP listing cursor')
                            seen.add(cursor)
                        else:
                            raise RuntimeQualificationError('MCP listing exceeds page bound')
                        results.append(validate_tool_schemas(profile, schemas))
    return {'profiles': results, 'tool_calls': 0, 'phone_actions': 0, 'model_calls': 0,
            'note': 'Isolated listing/schema qualification; no forensic accuracy or device qualification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schema-probe', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--repository', type=Path, default=ROOT)
    parser.add_argument('launcher', type=Path)
    args = parser.parse_args()
    try:
        if args.schema_probe:
            result = asyncio.run(asyncio.wait_for(schema_probe(args.launcher), timeout=90))
        else:
            result = qualify_runtime(args.launcher, args.repository)
        print(json.dumps(result, sort_keys=True))
    except ModuleNotFoundError as exc:
        print(json.dumps({'qualification_error': 'Missing qualification dependency: ' + str(exc.name)}))
        raise SystemExit(1)
    except Exception as exc:
        message = str(exc) if isinstance(exc, RuntimeQualificationError) else 'MCP qualification failed: ' + type(exc).__name__
        print(json.dumps({'qualification_error': message[:300]}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
