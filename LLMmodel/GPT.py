import openai 
import os
import ast
import time
import random as rd

openai.api_key = os.environ.get('openaikey')
os.environ["HTTP_PROXY"] = os.environ.get('httpproxy')
os.environ["HTTPS_PROXY"] = os.environ.get('httpproxy')

class GPT():
    def __init__(self, model="gpt-3.5-turbo-0613",temperature=0) -> None:
        self.model = model
        self.temperature = temperature
            
    def get_completion(self,prompt):
        messages = [{"role": "user", "content": prompt}]
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature, # this is the degree of randomness of the model's output
            )
        except Exception as e:
            print("Error:",e)
            time.sleep(rd.randint(1, 5))
            print("Second try, Use the same model")
            try:
                response = openai.ChatCompletion.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature, # this is the degree of randomness of the model's output
            )
            except Exception as e:
                print("Error:",e)
                time.sleep(rd.randint(1, 5))
                print("third try, Use the 16k model")
                self.model = "gpt-3.5-turbo-16k-0613"
                try:
                    response = openai.ChatCompletion.create(
                        model=self.model,
                        messages=messages,
                        temperature=self.temperature, # this is the degree of randomness of the model's output
                    )
                except Exception as e: 
                    print("Error:",e) 
        return response.choices[0].message["content"]


