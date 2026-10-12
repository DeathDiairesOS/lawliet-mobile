"""Local protocol smoke check; no credentials, device access or model calls."""
import asyncio
import json
import sys
import tempfile
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import PaginatedRequestParams


async def main():
    with tempfile.TemporaryDirectory(prefix='lawliet-mcp-check-') as folder:
        params = StdioServerParameters(command=sys.argv[1], args=['serve', '--db-dir', folder])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = set()
                cursor = None
                while True:
                    response = await session.list_tools(params=PaginatedRequestParams(cursor=cursor) if cursor else None)
                    names.update(tool.name for tool in response.tools)
                    cursor = response.next_cursor
                    if not cursor:
                        break
                required = {'run_aleapp', 'run_ileapp'}
                if not required <= names:
                    raise RuntimeError('Mobile tools missing from MCP: ' + str(required - names))
                print(json.dumps({'initialized': True, 'tools_advertised': len(names),
                                  'mobile_tools': sorted(required), 'note': 'Advertisement is not execution acceptance.'}))


if __name__ == '__main__':
    asyncio.run(asyncio.wait_for(main(), timeout=90))
