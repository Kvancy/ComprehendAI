import traceback
import idaapi
import idc
import idautils
import ida_xref
import json
import os
import asyncio

from idaapi import action_handler_t, UI_Hooks
from threading import Lock,Thread,Event
from openai import OpenAI
from enum import Enum

class TaskType(Enum):
    ANALYSIS = 1
    CUSTOM_QUERY = 2
    CUSTON_QUERY_WITH_CODE = 3

class QueryStatus(Enum):
    SUCCESS = 1
    FAILED = 2
    STOPPED = 3

#处理配置文件
class ConfigManager:
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        with cls._lock:
            if not cls._instance:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance
    
    def _initialize(self):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_path = os.path.join(self.script_dir, 'config.json')
        self.config = self._load_config()
        self.openai_client = self._create_openai_client()
        
    def _load_config(self):
        try:
            with open(self.config_path, "r") as f:
                return json.load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load config: {str(e)}")
    
    def _create_openai_client(self):
        return OpenAI(
            api_key=self.config["openai"]["api_key"],
            base_url=self.config["openai"]["base_url"]
        )
    
    @property
    def model_name(self):
        return self.config["openai"]["model"]
    
    @property
    def client(self):
        return self.openai_client
#处理反汇编代码提取
class DisassemblyProcessor:
    def __init__(self, max_depth=2):
        self.max_depth = max_depth
        self._lock = Lock()
        self._reset_state()
        
    def _reset_state(self):
        with self._lock:
            self.processed_funcs = set()
            self.func_disasm_list = []
    
    def get_current_function_disasm(self):
        self._reset_state()
        
        current_ea = idc.get_screen_ea()
        func_start = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
        
        if func_start == idaapi.BADADDR:
            raise ValueError("Failed to locate function start address")
            
        self._process_function(func_start, self.max_depth)
        return "\n".join(self.func_disasm_list)
    
    def _process_function(self, func_ea, depth):
        if func_ea in self.processed_funcs or depth < 0:
            return
            
        with self._lock:
            self.processed_funcs.add(func_ea)
        
        try:
            decompiled = str(idaapi.decompile(func_ea))
            with self._lock:
                self.func_disasm_list.append(decompiled)
        except Exception as e:
            print(f"Decompilation failed for {hex(func_ea)}: {str(e)}")
        
        for callee in self._get_callees(func_ea):
            self._process_function(callee, depth - 1)
    
    def _get_callees(self, func_ea):
        callees = set()
        for ea in range(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
            for xref in idautils.XrefsFrom(ea):
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    callee_ea = xref.to
                    if idc.get_func_attr(callee_ea, idc.FUNCATTR_START) == callee_ea:
                        callees.add(callee_ea)
        return callees
#处理openai接口相关
class AIService:
    def __init__(self):
        self.config = ConfigManager()
        self.stop_event = Event()

    def ask_ai(self, prompt, ai_isRunning:Lock):
        messages = [{"role": "user", "content": prompt}]
        print("ComprehendAI output:")
        self.stop_event.clear() #初始化事件
            
        result = self._request_openai(messages)
        ai_isRunning.release()  # 分析完成，无论成功失败都需释放锁

        match result:
            case QueryStatus.SUCCESS:
                print("\r✅ 分析完成！")
            case QueryStatus.FAILED:
                print("\r❌ 分析失败，请重试")
            case QueryStatus.STOPPED:
                print("\r✅ 分析暂停")
                

    def _request_openai(self,messages):
        reasoning_content = ""
        answer_content = ""
        is_answering = False
        try:
            completion = self.config.client.chat.completions.create(
            model=self.config.model_name,
            messages=messages,
            stream=True,
            )
            for chunk in completion:
                if self.stop_event.is_set():
                    raise StopIteration("任务被停止")

                # 如果chunk.choices为空，则打印usage
                if not chunk.choices:
                    print("\nUsage:")
                    print(chunk.usage)
                else:
                    delta = chunk.choices[0].delta
                    # 打印思考过程
                    if hasattr(delta, 'reasoning_content') and delta.reasoning_content != None:
                        print(delta.reasoning_content, end='', flush=True)
                        reasoning_content += delta.reasoning_content
                    else:
                        # 开始回复
                        if delta.content != "" and is_answering is False:
                            print("\n" + "=" * 20 + "完整回复" + "=" * 20 + "\n")
                            is_answering = True
                        answer_content += delta.content
                        
            print(answer_content)        
            return QueryStatus.SUCCESS
        
        except StopIteration as e:
            print(f"Error occurred: {e}")
            return QueryStatus.STOPPED

        except Exception as e:
            print(f"Error occurred: {e}")
            traceback.print_exc()
            return QueryStatus.FAILED
        
#处理用户接口
class AnalysisHandler:

    def __init__(self):
        self.disassembler = DisassemblyProcessor()
        self.ai_service = AIService()
        self.ai_isRunning = Lock()
        self.prompt = """
你是一名人工智能逆向工程专家。
我会提供你一些反汇编代码，其中首个函数是你需要分析并总结成报告的函数，
其余函数是该函数调用的一些子函数。
分析要求：
重点描述主函数功能，并对核心行为进行推测；
简要描述子函数功能

输出要求：
主函数功能：...
行为推测：...
子函数功能：...
纯文本输出。

下面是你要分析的反汇编代码：
"""
    def set_analysis_depth(self, depth):
        self.disassembler.max_depth = depth
    
    def _create_analysis_prompt(self, disassembly):
        return self.prompt + disassembly
    
    def _create_analysis_custom_query(self, disassembly,question):
        return question + disassembly
    
    def create_ai_task(self,taskType,question=""):

        match taskType:
            case TaskType.ANALYSIS:
                disassembly = self.disassembler.get_current_function_disasm()
                prompt = self._create_analysis_prompt(disassembly)
                self.async_task(prompt)
            case TaskType.CUSTOM_QUERY:
                self.async_task(question)    
            case TaskType.CUSTON_QUERY_WITH_CODE:
                disassembly = self.disassembler.get_current_function_disasm()
                prompt = self._create_analysis_custom_query(disassembly,question)
                self.async_task(prompt)
        
        
    def async_task(self,question):
        print(question)
        if self.ai_isRunning.acquire(blocking=False):
            task = Thread(target=self.ai_service.ask_ai,args=(question,self.ai_isRunning,)) 
            task.start()
            
        else:
            print("\r❌ 当前AI正在处理任务,请稍后尝试")
    
    def stop(self):
        self.ai_service.stop_event.set()

#处理插件框架
class ComprehendAIPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "AI-based Reverse Analysis Plugin"
    help = "Perform AI-based analysis on binary code"
    wanted_name = "ComprehendAI"
    wanted_hotkey = "Ctrl+Shift+A"

    ACTION_DEFINITIONS = [
        ("AI_analysis:Analysis", "Analysis", "执行非阻塞型AI分析"),
        ("AI_analysis:SetDepth", "Set analysis depth", "设置分析深度"),
        ("AI_analysis:SetPrompt", "Set your own prompt", "自定义prompt"),
        ("AI_analysis:CustomQueryWithCode", "Ask AI with code", "结合代码自定义提问"),
        ("AI_analysis:CustomQuery", "Ask AI", "自定义提问"),
        ("AI_analysis:Stop", "Stop", "停止"),
    ]

    def init(self):
        self.ui_hook = self.MenuHook()
        self.ui_hook.hook()
        
        self.handler = AnalysisHandler()
        self._register_actions()
        
        print("ComprehendAI initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.ui_hook.unhook()
        self._unregister_actions()
        print("ComprehendAI unloaded")

    def _register_actions(self):
        for action_id, label, tooltip in self.ACTION_DEFINITIONS:
            action_desc = idaapi.action_desc_t(
                action_id,
                label,
                self.MenuCommandHandler(action_id,self.handler),
                None,
                tooltip,
                0
            )
            idaapi.register_action(action_desc)

    def _unregister_actions(self):
        for action_id, _, _ in self.ACTION_DEFINITIONS:
            idaapi.unregister_action(action_id)

    class MenuHook(UI_Hooks):
        def finish_populating_widget_popup(self, form, popup):
            if idaapi.get_widget_type(form) in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
                for action_id, _, _ in ComprehendAIPlugin.ACTION_DEFINITIONS:
                    idaapi.attach_action_to_popup(form, popup, action_id, "ComprehendAI/", idaapi.SETMENU_APP)

    class MenuCommandHandler(action_handler_t):
        def __init__(self, action_id,handler:AnalysisHandler):
            super().__init__()
            self.action_id = action_id
            self.handler = handler
    
        def activate(self, ctx):     

            match self.action_id:
                case "AI_analysis:Analysis":
                    self.handler.create_ai_task(TaskType.ANALYSIS)
                case "AI_analysis:CustomQuery":
                    question = idaapi.ask_text(0, "", "输入问题")
                    if question:
                        self.handler.create_ai_task(TaskType.CUSTOM_QUERY, question)
                case "AI_analysis:SetDepth":
                    new_depth = idaapi.ask_long(2, "设置分析深度 (默认2):")
                    if new_depth is not None:
                        self.handler.set_analysis_depth(new_depth)       
                case "AI_analysis:SetPrompt":
                    yourPrompt = idaapi.ask_text(0, f"{self.handler.prompt}", "输入问题")
                    self.handler.prompt = yourPrompt
                case "AI_analysis:CustomQueryWithCode":
                    question = idaapi.ask_text(0, "", "输入问题")
                    if question:
                        self.handler.create_ai_task(TaskType.CUSTON_QUERY_WITH_CODE, question)
                case "AI_analysis:Stop":
                    self.handler.stop()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

def PLUGIN_ENTRY():
    return ComprehendAIPlugin()