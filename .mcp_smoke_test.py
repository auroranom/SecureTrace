import asyncio
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server = StdioServerParameters(
        command=str(Path(".venv/Scripts/python.exe").resolve()),
        args=["-m", "securetrace.mcp_server"],
        cwd=str(Path.cwd()),
    )

    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.list_tools()

            print("MCP connection: SUCCESS")
            print("Discovered tools:")
            for tool in result.tools:
                print(f"- {tool.name}")

            print(f"\nTotal tools discovered: {len(result.tools)}")

asyncio.run(main())
