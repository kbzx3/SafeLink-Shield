#importing libraries
from rich.console import Console
from rich import print
import pandas as pd , re , requests
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from groq import Groq
ai = Groq(
    api_key="key"
)  #replace key with Groq api key
api_key = 'key'
#replace key with virustotal api key
console = Console()
#function to print blue text
def bprint(text):
    box = f"{text}"
    console.print(box.replace(text, f"[blue]{text}[/blue]", 3))
#function to print red text
def rprint(text):
    box = f"{text}"
    console.print(box.replace(text, f"[red]{text}[/red]", 3))
#arranging and labeling the data
data = pd.read_csv('spam1.csv', encoding='ISO-8859-1')
X = data['v2']  
y = data['v1']  
X = X.fillna('').astype(str)
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)
vectorizer = CountVectorizer()
X_transformed = vectorizer.fit_transform(X)
#training the alg
X_train, X_test, y_train, y_test = train_test_split(X_transformed, y, test_size=0.01, random_state=42)
model = DecisionTreeClassifier()
model.fit(X_train, y_train)
#function to call on the groq api
def groq_check(message):
    try:
        system_prompt = {
                        "role": "system",
                        "content": "identify scam/spam/phishing links or messages and give 50-75 word responses on it, you are to not make conversation and just give an analysis on wether the message intends to scam a person or not, nothing else, the messages provided to you could be from any platfirm, do not mention the platform unless urgently needed, texts like 'hi how are you' or 'what the are not phishing messages, urgency does not nesseccarily mean scamming'"# system prompt to the groq AI
                    }

        user_message = {
            "role": "user",
            "content": f"{message}"
                    }
#message of the user
        messages = [system_prompt, user_message]

        chat_completion = ai.chat.completions.create(
                        messages=messages,
                        model="llama3-8b-8192"
                    )

        response= chat_completion.choices[0].message.content
        print(f"Groq: {response}")

    except Exception as e:
     print("Error:", e)
#function for the alg to identify links
def check_message(message):
    prediction = model.predict(vectorizer.transform([message]))

    if prediction[0]: 
        rprint("algorithm: Spam detected!")
        url_regex = re.compile(r'(https://\S+)') #detection for links
        match = url_regex.search(message)
        if match:
            print("Link found in the message.")
            url = match.group(0)
            #sending link to vt
            url_virustotal = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': api_key, 'resource': url}
            response = requests.get(url_virustotal, params=params)
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    if positives >= 1:
                        rprint("algorithm: The link is flagged as a scam.")
                    else:
                        bprint("algorithm: The link appears safe.")
                else:
                    bprint("algorithm: No data available for this URL.")
            else:
                bprint("algorithm: Error with the VirusTotal request.")
        else:
            bprint("algorithm: No URL found in the message.")
    else:
        bprint("algorithm: Message is not spam.")
#to take input to check
try:
    while True:
        message = input("Enter a message to check or exit to exit script: ")
        if message == "exit":
            print("exiting script")
            break
        else: 
            check_message(message)
            groq_check(message)
except KeyboardInterrupt: print("smth idk")
