import traceback
import idaapi
import idc
import idautils
import ida_xref
import json
import os
from idaapi import action_handler_t, UI_Hooks
from threading import Thread
from openai import OpenAI

processed_funcs = set()
FuncDisasmList = []
depth = 2


# 获取当前脚本所在目录
script_path = os.path.abspath(__file__)
script_dir = os.path.dirname(script_path)
config_path = os.path.join(script_dir, 'config.json')
print(config_path)

# OpenAI 客户端初始化
with open(config_path, "r") as f:
    config = json.load(f)

MODEL_NAME = config["openai"]["model"]
client = OpenAI(api_key=config["openai"]["api_key"], base_url=config["openai"]["base_url"])

# 动作常量
ACTION_ANALYSIS_1 = "AI_analysis:Blocking analysis"
ACTION_ANALYSIS_2 = "AI_analysis:Non-blocking analysis"
ACTION_SETDEPTH = "AI_analysis:Set depth"
ACTION_ASK = "AI_analysis:Ask"

def get_callees(func_ea):
    callees = set()
    for ea in range(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
        for xref in idautils.XrefsFrom(ea):
            if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                callee_ea = xref.to
                if idc.get_func_attr(callee_ea, idc.FUNCATTR_START) == callee_ea:
                    callees.add(callee_ea)
    return callees

def get_all_disasm(func_ea, max_depth=None):
    if func_ea in processed_funcs:
        return
    processed_funcs.add(func_ea)
    
    try:
        FuncDisasmList.append(str(idaapi.decompile(func_ea)))
    except Exception as e:
        print(f"Failed to decompile function at address {func_ea}: {e}")
    
    if max_depth is not None:
        if max_depth <= 0:
            return
        next_depth = max_depth - 1
    else:
        next_depth = None
    
    for callee_ea in get_callees(func_ea):
        get_all_disasm(callee_ea, next_depth)

def get_this_func_disasm(depth):
    processed_funcs.clear()
    FuncDisasmList.clear()
    current_ea = idc.get_screen_ea()
    func_start = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
    if func_start != idaapi.BADADDR:
        get_all_disasm(func_start, max_depth=depth)
    else:
        print("无法定位函数起始地址")
    
    disasm_all = "\n".join(FuncDisasmList)
    return disasm_all

def ask(messages):
    reasoning_content = ""
    answer_content = ""
    is_answering = False
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            stream=True,
        )

        for chunk in completion:
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
                    # 打印回复过程
                    # print(delta.content, end='', flush=True)
                    answer_content += delta.content
        return answer_content
    except Exception as e:
        print(f"Error occurred: {e}")
        traceback.print_exc()
        return None

def ask_thread_func(prompt):
    messages = [{"role": "user", "content": prompt}]
    print("⏳ 正在分析，请稍候...")
    result = ask(messages)
    if result:
        print("\r✅ 分析完成！")
        print(result)
    else:
        print("\r❌ 分析失败，请重试")

class AIAnalysisPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "AI-based Reverse Analysis Plugin"
    help = "Perform AI-based analysis on binary code"
    wanted_name = "ComprehendAI"
    wanted_hotkey = "Ctrl+Shift+A"

    def init(self):
        actions = [
            idaapi.action_desc_t(ACTION_ANALYSIS_1, "Non-blocking ComprehendAI", MenuHandler(ACTION_ANALYSIS_1), None, "非堵塞型AI分析", 0),
            idaapi.action_desc_t(ACTION_ANALYSIS_2, "Blocking ComprehendAI", MenuHandler(ACTION_ANALYSIS_2), None, "堵塞型AI分析", 0),
            idaapi.action_desc_t(ACTION_SETDEPTH, "Set analysis depth", MenuHandler(ACTION_SETDEPTH), None, "设置函数分析深度", 0),
            idaapi.action_desc_t(ACTION_ASK, "Ask AI", MenuHandler(ACTION_ASK), None, "手动输入任意问题", 0)
        ]
        
        for action in actions:
            idaapi.register_action(action)

        self.ui_hook = MenuHook()
        self.ui_hook.hook()

        print("ComprehendAI plugin initialized")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.ui_hook.unhook()
        for action in [ACTION_ANALYSIS_1, ACTION_ANALYSIS_2, ACTION_SETDEPTH, ACTION_ASK]:
            idaapi.unregister_action(action)
        print("ComprehendAI plugin unloaded")

class MenuHook(UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        widget_type = idaapi.get_widget_type(form)
        if widget_type in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
            actions = [ACTION_ANALYSIS_1, ACTION_ANALYSIS_2, ACTION_SETDEPTH, ACTION_ASK]
            for action in actions:
                idaapi.attach_action_to_popup(form, popup, action, "ComprehendAI/", idaapi.SETMENU_APP)

class MenuHandler(action_handler_t):
    def __init__(self, action):
        super().__init__()
        self.action = action

    def activate(self, ctx):
        if self.action == ACTION_ANALYSIS_1:
            self.non_blocking_analysis()
        elif self.action == ACTION_ANALYSIS_2:
            self.blocking_analysis()
        elif self.action == ACTION_SETDEPTH:
            self.set_depth()
        elif self.action == ACTION_ASK:
            self.ask_question()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def non_blocking_analysis(self):
        disasm_all = get_this_func_disasm(depth)
        prompt = f"""
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
{disasm_all}
"""
        print(f"prompt:{prompt}")
        t = Thread(target=ask_thread_func, args=(prompt,))
        t.start()

    def blocking_analysis(self):
        disasm_all = get_this_func_disasm(depth)
        prompt = f"""
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
{disasm_all}
"""
        print(f"prompt:{prompt}")
        messages = [{"role": "user", "content": prompt}]
        print("⏳ 正在分析，请稍候...")
        idaapi.show_wait_box("⏳ 正在分析，请稍候...")
        result = ask(messages)
        if result:
            print("\r✅ 分析完成！")
            print(result)
            idc.set_func_cmt(idc.get_screen_ea(), result, 1)
            idaapi.hide_wait_box()
        else:
            print("\r❌ 分析失败，请重试")

    def set_depth(self):
        global depth
        new_depth = idaapi.ask_long(2, "设置函数分析深度（默认为2）：")
        if new_depth is not None:
            depth = new_depth

    def ask_question(self):
        prompt = idaapi.ask_text(0, "", "输入问题")
        if prompt:
            t = Thread(target=ask_thread_func, args=(prompt,))
            t.start()

def PLUGIN_ENTRY():
    return AIAnalysisPlugin()



