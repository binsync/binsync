from daila.interfaces import OpenAIInterface

class OpenAIBSUser:
    def __init__(self, openai_api_key: str):
        self.ai_interface = OpenAIInterface(openai_api_key=openai_api_key)

    def run_all_ai_commands(self, func):
        pass

    def run_on_binary(self):
        pass
