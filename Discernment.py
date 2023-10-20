Prompts1 = '''
You are now a security expert familiar with Linux OS and CVE/CWE security knowledge.
Please determine whether the following function fragment limited by triple backticks is vulnerablede.
```{code}```
Let's follow the steps below "{chain}" to think through the problem step by step
You need to outline detailed thinking steps, and your answer needs to end with a final judgment in json format
json format 
"vulnerablity":only answer yes or no,
"influence Components":answer example (buffer or pointer or something else),
"reason":the reason for answers.
'''

from LLMmodel.GPT import GPT
import json


class Brain:
    def __init__(self, role, LLM = GPT()):
        self.LLM = LLM
        self.role = role

    def think(self, message):
        # 处理接受到的信息
        # TODO:analysis of INFO

        # 生成思考反馈
        feedback = f"{self.role}：我认为{message}，因为......"
        # ...

        return feedback


class chainAnalysis(Brain):
    def __init__(self, LLM = GPT(), verbose=1):
        super().__init__(role="chain", LLM=LLM)
        

    def clean_thinking_chain(self,verbose_chain:str,varlist:list):
        clean_chain = []
        oper_chain = verbose_chain.split("-->")[1].split("\n\n")
        for i in oper_chain:
            clean_chain.append(i)
            for j in varlist:               
                if j in i:
                    clean_chain.append(i)
                    break
        return clean_chain
    
    def _err_handle_func(self,err:str):
        results={
            "vulnerability":'No',
            "reason":-1,
            "part of influence":-1
        }
        try:
            match = err.split('{')[1]
            if len(match)>0:
                extracted_list = match.split(',')
                
                if "yes" in extracted_list[0] or "Yes" in extracted_list[0]:
                    results={
                    "vulnerability":'yes',
                    "reason":extracted_list[1].replace('}',"").replace("\"reason\":","").replace("\n",''),
                    "part of influence":extracted_list[2].replace('}',"").replace("\"part of influence\":","").replace("\n",'')
                }
        except:
            print("auto_prompts failure, whole text analysis...")
            results={
            "vulnerability":'failure',
            "reason":-1,
            "part of influence":-1
        }
        return results
    
    def get_dict_results(self,answer):
        start_index = answer.rfind('{')
        json_text = answer[start_index:]    

        try:
            data = json.loads(json_text)
        except:
            print("load json difficult, try to analyze str")
            data = self._err_handle_func(answer)

        return data

    def _result_add(self,dict_list):
        result_dict = {}
        for dict_item in dict_list:
            for key, value in dict_item.items():
                if key in result_dict:
                    result_dict[key].append(value)
                else:
                    result_dict[key] = [value]
                
        return result_dict
    def think(self, stepchain, beacon,code)->dict:
        res={
            "vulnerability":"no",
            "reason":"N/A",
            "part of influence":"N/A",
            "beacon":"N/A"
        }
        chains = stepchain
        if beacon == "auto_prompts":
            Template = f'''
            You are now a security expert familiar with Linux OS and CVE/CWE security knowledge.
            Please determine whether the following function fragment limited by triple backticks is vulnerablede.
            ```{code}```
            Let's followg the steps below "{chains}" to think through the question
            You need to outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
            A json must be contained at the end of your answer!
            json format: 
            "vulnerablity":only answer yes or no,
            "reason":Which step revealed that he had a problem,
            "part of influence":buffer or something else
            '''
            answer = self.LLM.get_completion(Template)
            res = self.get_dict_results(answer)
            if(res['vulnerability'].lower() == "yes" or res['vulnerability'].lower()=="no"):
                pass
            else:
                Template = f"""
                    Use this description"{chains}" to determine whether it exists security risk on the code.
                    give your answers in the following json format, and your answer must contain only one json!
                    json format 
                    "exists":only answer yes or no,
                    "reason":the reason for answers,
                    "part of influence":answer example (buffer or pointer or something else).
                """
                answer = self.LLM.get_completion(Template)
                res = self._err_handle_func(answer)
            if(res['vulnerability'].lower() == "yes"):res["beacon"] = beacon           
        else:
            for sentence in chains:
                Template = f'''
                Based on the analysis sentence limited by triple backticks.
                ```{sentence}```
                Check to see if the sentence is describing a code vulnerability.        
                you only need to answer yes or no.
                No more explanations!!
                '''
                answer = self.LLM.get_completion(Template)
                if "yes" in answer or "Yes" in answer :
                    
                    
                    think_more = f'''
                    Based on the analysis sentence limited by triple backticks.
                        ```{sentence}```
                        Check carefully if this is describing a problem that has been fixed, 
                        or if it is describing that the code is secure, 
                        or if it is a good practice.     
                        you only need to answer yes or no.
                        No more explanations!!
                    '''
                    think_result  = self.LLM.get_completion(think_more)
                    if "No" in think_result or "no" in think_result :
                            componentsanalysis  = f'''
                            Which components in the code are affected under this vulnerability description"{sentence}", 
                            your answer only needs to answer the component name, such as: pointer, memory.
                            No more explanations!!
                            '''
                            components  = self.LLM.get_completion(componentsanalysis)
                            res={
                                "vulnerability":"yes",
                                "reason":sentence,
                                "part of influence":components,
                                "beacon":beacon  
                            }
                            break
        return res
            
class cotSummaryAnalysis(Brain):
    def __init__(self, LLM = GPT(), verbose=1):
        super().__init__(role="chain", LLM=LLM)
        

    def clean_thinking_chain(self,verbose_chain:str,varlist:list):
        clean_chain = []
        oper_chain = verbose_chain.split("-->")[1].split("\n\n")
        for i in oper_chain:
            clean_chain.append(i)
        return clean_chain
    
    def _err_handle_func(self,err:str):
        results={
            "vulnerability":'No',
            "reason":-1,
            "part of influence":-1
        }
        try:
            match = err.split('{')[1]
            if len(match)>0:
                extracted_list = match.split(',')
                
                if "yes" in extracted_list[0] or "Yes" in extracted_list[0]:
                    results={
                    "vulnerability":'yes',
                    "reason":extracted_list[1].replace('}',"").replace("\"reason\":","").replace("\n",''),
                    "part of influence":extracted_list[2].replace('}',"").replace("\"part of influence\":","").replace("\n",'')
                }
        except:
            print("auto_prompts failure, whole text analysis...")
            results={
            "vulnerability":'failure',
            "reason":-1,
            "part of influence":-1
        }
        return results
    
    def get_dict_results(self,answer):    
        start_index = answer.rfind('{')  
        json_text = answer[start_index:]
        try:
            data = json.loads(json_text)
        except:
            print("load json difficult, try to analyze str")
            data = self._err_handle_func(answer)

        return data

    def _result_add(self,dict_list):
        result_dict = {}
        for dict_item in dict_list:
            for key, value in dict_item.items():
                if key in result_dict:
                    result_dict[key].append(value)
                else:
                    result_dict[key] = [value]
                
        return result_dict
    
    def think(self, stepchain, beacon,code)->dict:

        res={
            "vulnerability":"no",
            "reason":"N/A",
            "part of influence":"N/A",
            "beacon":"N/A"
        }
        chains = stepchain
        if beacon == "auto_prompts":
            Template = f'''
            You are now a security expert familiar with Linux OS and CVE/CWE security knowledge.
            Please determine whether the following function fragment limited by triple backticks is vulnerablede.
            ```{code}```
            Let's followg the steps below "{chains}" to think through the question
            You need to outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
            A json must be contained at the end of your answer!
            json format: 
            "vulnerablity":yes or no,
            "reason":Which step revealed that he had a problem,
            "part of influence":buffer or something else
            '''
            answer = self.LLM.get_completion(Template)
            res = self.get_dict_results(answer)
            if(res['vulnerability'].lower() == "yes" or res['vulnerability'].lower()=="no"):
                pass
            else:
                Template = f"""
                    Use this description"{chains}" to determine whether it exists security risk on the code.
                    give your answers in the following json format, and your answer must contain only one json!
                    json format 
                    "exists":only answer yes or no,
                    "reason":the reason for answers,
                    "part of influence":answer example (buffer or pointer or something else).
                """
                answer = self.LLM.get_completion(Template)
                res = self._err_handle_func(answer)
            if(res['vulnerability'].lower() == "yes"):res["beacon"] = beacon           
        else:
            last_chain = chains
            Template = f'''
                You are now a security expert familiar with Linux OS and CVE/CWE security knowledge.
                Please determine whether the following function fragment limited by triple backticks is vulnerable.
                ```{code}```
                Please determine whether there are any vulnerabilities in the corresponding code based on the summary section of this thinking chain:"{last_chain}", and analyze the reasons and influencing factors.
                You need to firstly elaborate on your thinking process before making a final judgment, and your answer needs to end with a final judgment in JSON format.
                A json must be contained at the end of your answer!
                json format: 
                "vulnerability": only answer yes or no,
                "reason": Which step revealed that there was a problem,
                "part of influence": buffer or something else
                '''
            answer = self.LLM.get_completion(Template)
            res = self.get_dict_results(answer)
            if(res['vulnerability'].lower() == "yes" or res['vulnerability'].lower()=="no"):
                pass
            else:
                Template = f"""
                    Use this description"{chains}" to determine whether it exists security risk on the code.
                    give your answers in the following json format, and your answer must contain only one json!
                    json format 
                    "exists":only answer yes or no,
                    "reason":the reason for answers,
                    "part of influence":answer example (buffer or pointer or something else).
                """
                answer = self.LLM.get_completion(Template)
                res = self._err_handle_func(answer)
            if(res['vulnerability'].lower() == "yes"):res["beacon"] = beacon 

        return res            

class Securityexpert(Brain):
    def __init__(self, LLM = GPT(), verbose=1):
        super().__init__(role="security expert", LLM=LLM)

    def _err_handle_func(self,res:str):
        results={
            "vulnerability":'No',
            "influence components":-1,
            "reason":-1
        }
        match = res.split('{')[1]
        if len(match)>0:
            extracted_list = match.split(',')
            if "yes" in extracted_list[0].lower():
                results={
                "vulnerability":'yes',
                "influence components":extracted_list[1].replace('}',"").replace("\"influence Components\":","").replace("\n",'').replace("\"",""),
                "reason":extracted_list[2].replace('}',"").replace("\"reason\":","").replace("\n",'')
            }
        return results
    def _to_dict(self,res:str):
        results={
            "vulnerability":'No',
            "influence components":-1,
            "reason":-1
        }
        match = res.split('{')[1]
        analysis_str = "{"+match
        try:
            parse_dict = json.loads(analysis_str)
            res = parse_dict
            first_key = list(parse_dict.keys())[0] 
            first_value = parse_dict[first_key] 
            results["vulnerability"] =parse_dict["exists"]
            results["influence components"] = parse_dict["influence Components"]
            results["reason"] = parse_dict["reason"]
            if("yes" != first_value.lower()):
                if("no" != first_value.lower()):
                    try:
                        flag = len(parse_dict["influence Components"])
                    except:
                        flag = 0
                    if(flag>0):
                        print("unknown answer transfer yes")
                        results["vulnerability"] ="Yes"
                        results["influence components"] = parse_dict["influence Components"]
                        results["reason"] = parse_dict["reason"]
                    else:
                        print("unknown answer transfer no")
                        results["vulnerability"] ="No"
                        results["influence components"] = parse_dict["influence Components"]
                        results["reason"] = parse_dict["reason"]
            
        except :
            print("Could not parse dict")
            res = self._err_handle_func(analysis_str)
        
        return results
    
  
    
    def think(self, code, chain)->dict: 
        Template = f"""
            Use this description"{chain}" to determine whether exists security risk.
            The determination should follow a strict review method, should not assume that any input is legal,
            You need to outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
            A json must be contained at the end of your answer!
            json format 
            "exists":only answer yes or no,
            "influence Components":answer example (buffer or pointer or something else),
            "reason":the reason for answers. 
        """
        answer = self.LLM.get_completion(Template)
        result = self._to_dict(answer)
        return result

class SecSystem(Brain):
    def __init__(self, LLM = GPT(), verbose=1):
        super().__init__(role="chain", LLM=LLM)
    
    def _err_handle_func(self,res:str):
        results={
            "vulnerability":'No',
            "influence components":-1,
            "reason":-1
        }
        match = res.split('{')[1]
        if len(match)>0:
            extracted_list = match.split(',')
            if "yes" in extracted_list[0].lower():
                results={
                "vulnerability":'yes',
                "influence components":extracted_list[1].replace('}',"").replace("\"influence Components\":","").replace("\n",'').replace("\"",""),
                "reason":extracted_list[2].replace('}',"").replace("\"reason\":","").replace("\n",'')
            }
        return results
    def _to_dict(self,res:str, beacon=[]):
        results={
            "vulnerability":'No',
            "influence components":-1,
            "reason":-1
        }
        match = res.split('{')[1]
        analysis_str = "{"+match
        try:
            parse_dict = json.loads(analysis_str)
            res = parse_dict
            first_key = list(parse_dict.keys())[0] 
            first_value = parse_dict[first_key] 
            results["vulnerability"] =parse_dict["vulnerability"]
            results["influence components"] = parse_dict["influence Components"]
            results["reason"] = parse_dict["reason"]
            if("yes" != first_value.lower()):
                if("no" != first_value.lower()):
                    try:
                        flag = len(parse_dict["influence Components"])
                        if parse_dict["influence Components"] == "unknown":
                            flag = 0
                        if parse_dict["influence Components"] == "N/A":
                            flag = 0
                        if("auto_prompts" not in beacon):
                            flag = 1
                    except:
                        flag = 0
                    if(flag>0):
                        print("unknown answer transfer yes")
                        results["vulnerability"] ="Yes"
                        results["influence components"] = parse_dict["influence Components"]
                        results["reason"] = parse_dict["reason"]
                    else:
                        print("unknown answer transfer no")
                        results["vulnerability"] ="No"
                        results["influence components"] = parse_dict["influence Components"]
                        results["reason"] = parse_dict["reason"]
            
        except :
            print("Could not parse dict")
            res = self._err_handle_func(analysis_str)
        
        return results
    
    def think(self, code, chain, beacon)->dict: 
        if("auto_prompts" not in beacon):
            print("serious mode")
            Template = f"""
                Here is some Auxiliary Information "{chain}" to discribe some information for the code.
                We suspect these vulnerabilities [{beacon}] in the code.
                I need you to act as a vulnerability detection system.the first request is "whether the following function fragment limited by triple backticks is vulnerablede.
                ```{code}```"
                Your answer must outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
                A json must be contained at the end of your answer!
                json format 
                "vulnerability":only answer yes or no,
                "influence Components":answer example (buffer or pointer or something else),
                "reason":the reason for answers. 
            """
        else:
            print("easy mode")
            Template = f"""
                Here is some Auxiliary Information "{chain}" to discribe some information for the code.
                I need you to act as a vulnerability detection system.the first request is "whether the following function fragment limited by triple backticks is vulnerablede.
                ```{code}```"
                Your answer must outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
                A json must be contained at the end of your answer!
                json format 
                "vulnerability":only answer yes or no,
                "influence Components":answer example (buffer or pointer or something else),
                "reason":the reason for answers. 
            """
        answer = self.LLM.get_completion(Template)
        result = self._to_dict(answer,beacon)
        return result
       
class DeepSec(Brain):
    def __init__(self, LLM = GPT(), verbose=1 ,mode="normal"):
        super().__init__(role="chain", LLM=LLM)
        self.mode = mode
    
    def _err_handle_func(self,res:str):
        results={
            "vulnerability":'No',
            "influence components":-1,
            "reason":-1
        }
        match = res.split('{')[1]
        if len(match)>0:
            extracted_list = match.split(',')
            if "yes" in extracted_list[0].lower():
                results={
                "vulnerability":'yes',
                "influence components":extracted_list[1].replace('}',"").replace("\"influence Components\":","").replace("\n",'').replace("\"",""),
                "reason":extracted_list[2].replace('}',"").replace("\"reason\":","").replace("\n",'')
            }
        return results
    
    def _unknown_flag(self, judge:str)->bool:
        flag = False
        if("yes" != judge.lower()):
            if("no" != judge.lower()):
                flag = True
        return flag
    

    def _to_dict(self,res:str, beacon=[]):
        results={
            "vulnerability":'No',
            "influence components":-1,
            "reason":-1
        }
        match = res.split('{')[1]
        analysis_str = "{"+match
        
        try:
            parse_dict = json.loads(analysis_str)
            res = parse_dict

            first_key = list(parse_dict.keys())[0] 
            first_value = parse_dict[first_key] 
            results["vulnerability"] =parse_dict["vulnerability"]
            results["influence components"] = parse_dict["influence components"]
            results["reason"] = parse_dict["reason"]
            if self._unknown_flag(first_value):
                if self.mode == "abstrict":
                    print("unknown answer transfer yes")
                    results["vulnerability"] ="Yes"
                    results["influence components"] = parse_dict["influence components"]
                    results["reason"] = parse_dict["reason"]
                elif self.mode == "strict" :
                    try:
                        flag = len(parse_dict["influence components"])
                        # Prefer beacon to think that if there is a loophole, it means there is a loophole.
                        if parse_dict["influence components"] == "unknown":
                            flag = 0
                        if parse_dict["influence components"] == "n/a":
                            flag = 0
                        if("auto_prompts" not in beacon):
                            flag = 1
                    except:
                        flag = 0
                    if(flag>0):
                        print("unknown answer transfer yes")
                        results["vulnerability"] ="Yes"
                        results["influence components"] = parse_dict["influence components"]
                        results["reason"] = parse_dict["reason"]
                    else:
                        print("unknown answer transfer no")
                        results["vulnerability"] ="No"
                        results["influence components"] = parse_dict["influence components"]
                        results["reason"] = parse_dict["reason"]
                elif self.mode == "ease":
                    try:
                        if("auto_prompts" not in beacon):
                            flag = 1
                        flag = len(parse_dict["influence components"])
                        # Prefer large models to find out the loopholes yourself.
                        if parse_dict["influence components"] == "unknown":
                            flag = 0
                        if parse_dict["influence components"] == "n/a":
                            flag = 0
                    except:
                        flag = 0
                    if(flag>0):
                        print("unknown answer transfer yes")
                        results["vulnerability"] ="Yes"
                        results["influence components"] = parse_dict["influence components"]
                        results["reason"] = parse_dict["reason"]
                    else:
                        print("unknown answer transfer no")
                        results["vulnerability"] ="No"
                        results["influence components"] = parse_dict["influence components"]
                        results["reason"] = parse_dict["reason"]
                elif self.mode == "abease":
                    print("unknown answer transfer no")
                    results["vulnerability"] ="No"
                    results["influence components"] = "N/A"
                    results["reason"] = parse_dict["reason"]   
                else:
                    print("Normal answer transfer yes strict")
                    print("unknown answer transfer yes")
                    results["vulnerability"] ="Yes"
                    results["influence components"] = parse_dict["influence components"]
                    results["reason"] = parse_dict["reason"]
            
        except Exception as e:
            print("Could not parse dict : {}".format(str(e)))
            res = self._err_handle_func(analysis_str)
        
        return results
    
    def think(self, code, chain, beacon)->dict: 
        
        if self.mode == "abstrict":
            print(self.mode)
            Template = f"""
                Here is some Auxiliary Information "{chain}" to discribe some information for the code.
                There are some vulnerabilities in the code. I need you to act as a vulnerability detection system.the first request is "Help me find the vulnerabilities in the following function fragment limited by triple backticks and analysis it.
                ```{code}```"
                Your answer must outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
                A json must be contained at the end of your answer!
                json format 
                "vulnerability":only answer yes or no,
                "influence Components":answer example (buffer or pointer or something else),
                "reason":the reason for answers. 
            """
        elif self.mode == "strict":
            print(self.mode)
            vulist = []
            for i in beacon:
                if i == "auto_prompts":
                    vulist.append("potential vulnerability")
                if i == "unknown":
                    vulist.append("potential vulnerability")
                else:
                    vulist.append(i)
            Template = f"""
                Here is some Auxiliary Information "{chain}" to discribe some information for the code.
                We suspect these vulnerabilities [{vulist}] in the code.
                I need you to act as a vulnerability detection system.the first request is "whether the following function fragment limited by triple backticks is vulnerablede.
                ```{code}```"
                 Before your answer was given, you must know the code should be judged to be free of vulnerabilities unless there is conclusive evidence.
                Your answer must outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
                A json must be contained at the end of your answer!
                json format 
                "vulnerability":only answer yes or no,
                "influence Components":answer example (buffer or pointer or something else),
                "reason":the reason for answers. 
            """
        elif self.mode == "ease":
            print(self.mode)
            Template = f"""
                Here is some Auxiliary Information "{chain}" to discribe some information for the code.
                I need you to act as a vulnerability detection system.the first request is "whether the following function fragment limited by triple backticks is safe.
                ```{code}```"
               
                Fully consider not to generate useless false positives!
                Your answer must outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
                A json must be contained at the end of your answer!
                json format 
                "vulnerability":only answer yes or no,
                "influence Components":answer example (buffer or pointer or something else),
                "reason":the reason for answers. 
            """
        elif self.mode == "abease":
            print(self.mode)
            Template = f"""
                Here is some Auxiliary Information "{chain}" to discribe some information for the code.
                I need you to act as a vulnerability detection system.the first request is "please confirm whether the following function fragment limited by triple backticks is safe.
                ```{code}```"
                Fully consider not to generate useless false positives!
                Your answer must outline detailed thinking steps, and your answer needs to end with a final judgment in json format.
                A json must be contained at the end of your answer!
                json format 
                "vulnerability":only answer yes or no,
                "influence Components":answer example (buffer or pointer or something else),
                "reason":the reason for answers. 
            """
        
        answer = self.LLM.get_completion(Template).lower()
        result = self._to_dict(answer,beacon)
        return result
    


class Detector:
    def __init__(self, parameters, LLM = GPT(), varlist = [], beacon = [], mode = "normal"):

        self.LLM = LLM
        self.parameters = parameters
        self.varlist = varlist
        self.beacon = beacon
        self.mode = mode

    
    '''
    description: 
    param {*} self
    param {*} dict_list
    return {*}
    '''    
    def _result_add(self,dict_list):
        result_dict = {}
        for dict_item in dict_list:
            for key, value in dict_item.items():
                if key in result_dict:
                    result_dict[key].append(value)
                else:
                    result_dict[key] = [value]
                
        return result_dict
    
    def detect(self, judge:list):
        lst_lower = [s.lower() for s in judge]    
        if "yes" in lst_lower:
            result = 1
        else:
            result = 0
        return result
    
    def analysis(self, code, informations:str):
        tmp = []

        if(self.parameters == "secsystem"):
            sec = SecSystem()
            for info in informations:
                res = sec.think(code,info.split("-->")[1],self.beacon)
                tmp.append(res)

        if(self.parameters == "deepsec"):
            sec = DeepSec(mode=self.mode)
            for info in informations:
                res = sec.think(code,info.split("-->")[1],self.beacon)
                tmp.append(res)

        if (self.parameters == "secexp"):
            sec = Securityexpert()
            for info in informations:
                res = sec.think(code,info.split("-->")[1])
                tmp.append(res)
            

        if (self.parameters == "stepthinking"):
            cA = chainAnalysis()
            for info in informations:
                stepchain=cA.clean_thinking_chain(info,self.varlist)
                res = cA.think(stepchain,info.split("-->")[0].replace("-"*40+"COT"+"-"*40 + "\n",""),code)
                tmp.append(res)
        
        if(self.parameters == "cot_summary_thinking"):
            cA = cotSummaryAnalysis()
            for info in informations:
                stepchain=cA.clean_thinking_chain(info,self.varlist)
                res = cA.think(stepchain,info.split("-->")[0].replace("-"*40+"COT"+"-"*40 + "\n",""),code)
                tmp.append(res)

        result = self._result_add(tmp)
        return result
    
    