import asyncio

from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import mcp.server.stdio
#import crypto_utils
from hsm import hsm_utils
import base64
import json

notes: dict[str, str] = {}

server = Server("crypto")

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """
    List available hsm resources。
    比如：可用的密码机、没有密钥等。
    """
    return None

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific note's content by its URI.
    The note name is extracted from the URI host component.
    """
    return None

@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    """
    List available prompts.
    Each prompt can have optional arguments to customize its behavior.
    """
    return None

@server.get_prompt()
async def handle_get_prompt(
    name: str, arguments: dict[str, str] | None
) -> types.GetPromptResult:
    return None

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available hsm crypto tools.
    """
    return [
        types.Tool(
            name="sm2-sign",
            description="使用HSM硬件SM2密钥进行数据签名",
            inputSchema={
                "type": "object",
                "properties": {
                    "plaintext": {"type": "string", "description": "待签名数据，最大长度4KB"},
                    "key_index": {"type": "integer", "description": "HSM中预置的SM2密钥索引(1-100)"}
                },
                "required": ["plaintext", "key_index"],
                "examples": [{
                    "plaintext": "我是明文内容",
                    "key_index": 1
                }]
            },
        ),
        types.Tool(
            name="sm4-encrypt",
            description="使用HSM硬件的外部SM4密钥进行数据加密",
            inputSchema={
                "type": "object",
                "properties": {
                    "plaintext": {"type": "string", "description": "待加密数据"},
                    "external_key": {"type": "string", "description": "16字节的外部密钥(base64编码)"}
                },
                "required": ["plaintext", "external_key"],
                "examples": [{
                    "plaintext": "我是明文内容",
                    "external_key": "MTIzNDU2NzgxMjM0NTY3OA=="
                }]
            },
        ),
        types.Tool(
            name="sm4-decrypt",
            description="使用HSM硬件的外部SM4密钥进行数据解密",
            inputSchema={
                "type": "object",
                "properties": {
                    "ciphertext": {"type": "string", "description": "密文(base64编码)"},
                    "external_key": {"type": "string", "description": "与加密相同的密钥(base64)"}
                },
                "required": ["ciphertext", "external_key"],
                "examples": [{
                    "ciphertext": "L5Ksh9Gc...",
                    "external_key": "MTIzNDU2NzgxMjM0NTY3OA=="
                }]
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Handle hsm crypto tool execution requests.
    """
    if not arguments:
        raise ValueError("Missing arguments")

    try:
        if name == "sm2-sign":
            # SM2签名
            signature = hsm_utils.sm2_sign(
                plaintext=arguments["plaintext"],
                key_index=str(arguments["key_index"])
            )
            return {
                "signature": signature['signature']
            }

        elif name == "sm4-encrypt":
            # SM4加密增强
            raw_key = base64.b64decode(arguments["external_key"])
            
            encrypted = hsm_utils.sm4_encrypt(
                arguments["plaintext"],
                external_key=raw_key
            )
            return {
                "ciphertext": base64.b64encode(encrypted).decode()
            }

        elif name == "sm4-decrypt":
            # SM4解密增强
            raw_data = base64.b64decode(arguments["ciphertext"])
            decrypted = hsm_utils.sm4_decrypt(
                ciphertext=raw_data,
                external_key=base64.b64decode(arguments["external_key"])
            )
            return {"plaintext": decrypted}

        else:
            raise ValueError(f"Unsupported HSM operation: {name}")

    except KeyError as e:
        raise ValueError(f"mcp-hsm 参数缺失: {str(e)}") from e
    except Exception as e:
        error_detail = {
            "code": hex(getattr(e, 'errno', 0xFFFFFFFF)),
            "module": "mcp-hsm",
            "advice": "请检查密钥索引是否正确或联系HSM管理员"
        }
        raise ValueError(f"MCP安全操作失败: {str(e)} | {json.dumps(error_detail)}")

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="MCP-HSM Server",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())