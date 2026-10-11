"""Call one pyghidra-mcp tool over streamable-http and print the result (grm-haj3).

The PyPI release ships no CLI client; this is the minimal one, on the `mcp` library the server
already depends on.

usage: query.py <tool> [json-args]      (tool 'tools' lists the server's tools)
  query.py disassemble '{"binary_name":"smb.nes","address":"8000","count":20}'
"""
import asyncio
import json
import os
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

URL = f"http://127.0.0.1:{os.environ.get('GRM_MCP_PORT', '8765')}/mcp"


async def main(tool, args):
    async with streamablehttp_client(URL) as (read, write, _):
        async with ClientSession(read, write) as s:
            await s.initialize()
            if tool == "tools":
                for t in (await s.list_tools()).tools:
                    print(t.name, "-", (t.description or "").splitlines()[0])
                return
            r = await s.call_tool(tool, args)
            for c in r.content:
                print(getattr(c, "text", c))
            if r.isError:
                sys.exit(1)


asyncio.run(main(sys.argv[1], json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}))
