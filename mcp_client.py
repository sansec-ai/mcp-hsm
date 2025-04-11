import asyncio, os, json, ast
from typing import Optional
from contextlib import AsyncExitStack

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import dashscope, openai
from dashscope import Generation
from dashscope.api_entities.dashscope_response import (GenerationResponse,DashScopeAPIResponse)
from dotenv import load_dotenv
from http import HTTPStatus

load_dotenv()  # load environment variables from .env

class MCPClient:
    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        if os.getenv('OPENAI_API_KEY'):
            openai.api_key = os.getenv('OPENAI_API_KEY')
            openai.base_url = os.getenv('OPENAI_API_BASE', "https://api.openai.com/v1/")
            self.api_mode = 'openai'
        else:
            dashscope.api_key = os.getenv('DASHSCOPE_API_KEY')
            self.api_mode = 'dashscope'
    async def _call_llm_api(self, messages, tools):
        """统一的大模型调用接口"""
        if self.api_mode == 'dashscope':
            return Generation.call(
                model='qwen-plus',
                messages=messages,
                tools=tools,
                result_format='message'
            )
        elif self.api_mode == 'openai':
            # 转换工具格式为OpenAI兼容格式
            openai_tools = [{
                "type": "function",
                "function": {
                    "name": tool['function']['name'],
                    "description": tool['function']['description'],
                    "parameters": tool['function']['parameters']
                }
            } for tool in tools]
            
            return await openai.ChatCompletion.acreate(
                model=os.getenv('LLM_MODEL', 'qwq-32b'),
                messages=messages,
                tools=openai_tools,
                tool_choice="auto"
            )

    def _normalize_response(self, response):
        """统一不同API的响应格式"""
        if self.api_mode == 'dashscope':
            return {
                'content': response.output.choices[0].message.get('content', ''),
                'tool_calls': response.output.choices[0].message.get('tool_calls', []),
                'role': response.output.choices[0].message.get('role', 'assistant')
            }
        elif self.api_mode == 'openai':
            msg = response.choices[0].message
            return {
                'content': msg.content,
                'tool_calls': msg.tool_calls,
                'role': msg.role
            }
    async def connect_to_server(self, server_script_path: str):
        """Connect to an MCP server
        
        Args:
            server_script_path: Path to the server script (.py or .js)
        """
        is_python = server_script_path.endswith('.py')
        is_js = server_script_path.endswith('.js')
        if not (is_python or is_js):
            raise ValueError("Server script must be a .py or .js file")
            
        command = "python" if is_python else "node"
        server_params = StdioServerParameters(
            command=command,
            args=[server_script_path],
            env=None
        )
        
        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
        
        await self.session.initialize()
        
        # List available tools
        response = await self.session.list_tools()
        tools = response.tools
        print("\nConnected to server with tools:", [tool.name for tool in tools])
    async def process_query(self, query: str, test_resp=None) -> str:
        """Process a query using LLM and available tools"""
        if query == "":
            return "Query cannot be empty."
        messages = [
            {"role": "system", "content": "你是一个专业的密码学算法助手，精通各类国际密码算法和GM标准算法。\\n#密码算法步骤：1.用户需要提供密钥ID 2.如果用户未提供密钥ID，则可调用query_keys查询密钥列表，并使用第1个符合条件的密钥ID。如果密钥列表为空，则需要调用generate_key生成密钥。"},
            {
                "role": "user",
                "content": query
            }
        ]

        try:
            tools_response  = await self.session.list_tools()
            available_tools = [{
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema  # Must be JSON Schema format
                }
                } for tool in tools_response.tools]
            final_text = []
            # print("Formatted tools:", json.dumps(available_tools, indent=2))
            # prompt_list = await self.session.list_prompts()
            
            err_cnt = 0
            while True:
                # API调用
                if test_resp:
                    api_resp = DashScopeAPIResponse(
                    request_id=test_resp["request_id"],
                    status_code=HTTPStatus.OK,
                    output=test_resp["output"])
                    raw_response = GenerationResponse.from_api_response(api_resp)
                    response = self._normalize_response(raw_response)
                    test_resp = None
                else:
                    raw_response = await self._call_llm_api(messages, available_tools)
                    response = self._normalize_response(raw_response)
                    #print(f"response={response}")

                # Validate API response
                if not response:
                    raise ValueError(f"Empty API response :{response}")

                message_content = response['content']
                tool_calls = response['tool_calls']
                role = response['role']
                    
                if not message_content and not tool_calls:
                    return "No response generated :{response}"
                
                # 无工具调用时处理
                if not tool_calls:
                    if isinstance(message_content, str):
                        return message_content
                    return "未识别响应格式"
                
                # 检查如果message如果有role且content非控，则print content ，并附加到messages
                if role :
                    print(f"{role}: {message_content}")
                    # messages.append({
                    #     "role": choice.message.role,
                    #     "content": self._convert_to_bailian_format(choice.message.content)
                    # })
                # 记录assistant消息
                if message_content or message_content == "":
                    message_content = " "
                assistant_msg = {
                    "role": role,
                    "content": message_content
                }
                
                assistant_msg["tool_calls"] = [
                        {
                            "id": tc.id if self.api_mode == 'openai' else tc["id"],
                            "function": {
                                "name": tc.function.name if self.api_mode == 'openai' else tc["function"]["name"],
                                "arguments": tc.function.arguments if self.api_mode == 'openai' else tc["function"]["arguments"]
                            },
                            "type": "function"
                        } for tc in tool_calls
                ]
                
                messages.append(assistant_msg)            
                # Handle tool calls
                for tool_call in tool_calls:
                    try:
                        tool_name = tool_call["function"]["name"]
                        tool_args = self._parse_arguments(tool_call["function"]["arguments"])

                        print(f"执行工具调用：{tool_name}，参数：{tool_args}")                        
                        # 执行工具调用
                        result = await self.session.call_tool(tool_name, tool_args)
                        if result.isError:
                            print(f"工具调用失败，参数：{tool_args}，失败原因：{result.content}")
                            messages.append({
                                "role": "tool",
                                "content": f"工具调用失败：，参数：{tool_args}，{result.content}",
                                "tool_call_id": tool_call["id"]
                            })
                            err_cnt += 1
                            if err_cnt > 3:
                                return "工具调用失败次数过多，请重试"
                            continue
                        
                        # 添加结果到消息历史
                        messages.append({
                            "role": "tool",
                            "content": self._convert_to_bailian_format(result.content),
                            "tool_call_id": tool_call["id"]
                        })
                    
                    except Exception as e:
                        print(f"工具调用失败：{str(e)}")
                        messages.append({
                            "role": "tool",
                            "content": f"工具调用失败：{str(e)}",
                            "tool_call_id": tool_call["id"]
                        })
                        err_cnt += 1
                        if err_cnt > 3:
                            return "工具调用失败次数过多，请重试"
                    # 验证消息顺序
                    self._validate_message_sequence(messages)
        
        except Exception as e:
            #return f"Error: {str(e)}"
            raise e

    async def chat_loop(self):
        """Run an interactive chat loop"""
        print("\nMCP Client Started!")
        print("Type your queries or 'quit' to exit.")
        # response = await self.process_query("")
        # print("\n" + response)
        
        while True:
            try:
                query = input("\nQuery: ").strip()
                
                if query.lower() == 'quit':
                    break
                    
                response = await self.process_query(query)
                print("\n" + response)
                    
            except Exception as e:
                print(f"\nError: {str(e)}")
    
    async def cleanup(self):
        """Clean up resources"""
        await self.exit_stack.aclose()
    def _parse_arguments(self, raw_args: str) -> dict:
        try:
            return json.loads(raw_args)
        except json.JSONDecodeError as e:
            # print(f"JSON解析失败，原始参数：{raw_args}")
            try:
                fixed_args = raw_args.replace("'", '"')
                return json.loads(fixed_args)
            except json.JSONDecodeError as e2:
                print(f"修复引号后仍失败：{e2}")
                try:
                    return ast.literal_eval(raw_args)
                except Exception as e3:
                    print(f"字面量解析失败：{e3}")
                    raise ValueError("无法解析工具参数")
    def _validate_message_sequence(self, messages: list):
        """验证消息顺序是否符合百炼要求"""
        for i, msg in enumerate(messages):
            if msg["role"] == "tool":
                if i == 0 or messages[i-1]["role"] != "assistant":
                    raise ValueError("Tool message must follow assistant message")
                if "tool_calls" not in messages[i-1]:
                    raise ValueError("Previous assistant message lacks tool_calls")
    def _convert_to_bailian_format(self, content) -> str:
        """将MCP内容类型转换为阿里云百炼兼容格式"""
        if isinstance(content, list):
            return "\n".join([self._convert_item(c) for c in content])
        return self._convert_item(content)

    def _convert_item(self, item) -> str:
        """转换单个内容项"""
        if hasattr(item, 'text'):
            return item.text
        if hasattr(item, 'data'):
            return json.dumps(item.data)
        return str(item)

async def main():
    if len(sys.argv) < 2:
        print("Usage: python client.py <path_to_server_script>")
        sys.exit(1)
        
    client = MCPClient()
    try:
        await client.connect_to_server(sys.argv[1])
        await client.chat_loop()
    finally:
        await client.cleanup()

if __name__ == "__main__":
    import sys
    asyncio.run(main())
