from flask import Flask, request, jsonify
from urllib.parse import urlparse
import ipaddress
import re
import whois
import urllib.request
from bs4 import BeautifulSoup
from datetime import datetime
import requests
import socket
import xgboost as xgb
import pandas as pd
import openai
import json
#  pip install openai==0.28

app = Flask(__name__)

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

model = xgb.XGBClassifier(learning_rate=0.4, max_depth=7)
model.load_model('TrainedModel.bst')


# Define the feature extraction functions
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip


def haveAtSign(url):
    return 1 if "@" in url else 0


def getLength(url):
    return 0 if len(url) < 54 else 1


def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth += 1
    return depth


def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 and pos > 7 else 0


def httpDomain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0


def tinyURL(url):
    match = re.search(shortening_services, url)
    return 1 if match else 0


def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0


def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = \
            BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(),
                          "xml").find(
                "REACH")['RANK']
        rank = int(rank)
    except Exception:
        return 0
    return 1 if rank < 100000 else 0


def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        return 1 if ((ageofdomain / 30) < 6) else 0


def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None):
        return 1
    elif (type(expiration_date) is list):
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        return 0 if ((end / 30) < 6) else 1


def iframe(response):
    if response == "" or response.status_code != 200:
        return 1
    else:
        return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1


def mouseOver(response):
    if response == "" or response.status_code != 200:
        return 1
    else:
        return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0


def rightClick(response):
    if response == "" or response.status_code != 200:
        return 1
    else:
        return 0 if re.findall(r"event.button ?== ?2", response.text) else 1


def forwarding(response):
    if response == "" or response.status_code != 200:
        return 1
    else:
        return 0 if len(response.history) <= 2 else 1


def featureExtraction(url):
    features = []
    features.append(getDomain(url))
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    dns = 0
    try:
        domain_name = whois.whois(urlparse(url).netloc)
    except socket.error:
        dns = 1
    except:
        dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(0 if dns == 1 else domainAge(domain_name))
    features.append(0 if dns == 1 else domainEnd(domain_name))

    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features


@app.route('/extract_features', methods=['POST'])
def extract_features():
    data = request.json
    url = data.get('url')
    features = featureExtraction(url)
    return jsonify(features)


def run_prediction(input_features):
    global model
    columns = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 'https_Domain', 'TinyURL',
               'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over',
               'Right_Click', 'Web_Forwards']
    input_df = pd.DataFrame([input_features], columns=columns)
    return model.predict(input_df)[0]


# Function to detect if a URL is phishing or legitimate
def detect_phishing(url):
    initiator_text = """
    You are a cybersecurity assistant specializing in detecting phishing URLs.
    You will analyze the given URL and predict whether it is a phishing site or a legitimate site.
    Please output the data in form of JSON returning the prediction.
    JSON should be something like {'prediction': 0} for phishing and {'prediction': 1} for legitimate.
    """

    generated_prompt = f"Below is the URL you need to analyze.\n{url}"

    print("#")
    print(generated_prompt)
    print("#")

    openai.api_key = "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"
    print("\n\n\n\n", openai.api_key, "\n\n\n\n")

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": initiator_text},
                {"role": "user", "content": generated_prompt},
            ]
        )
    except openai.error.OpenAIError as e:
        raise Exception(f"Error while predicting phishing: {e}")

    try:
        prediction = json.loads(response['choices'][0]['message']['content'])
    except json.JSONDecodeError as e:
        raise Exception(f"Error while parsing response: {e}")

    return prediction



@app.route('/detect_phishing', methods=['POST'])
def detect_phishing_endpoint():
    try:
        data = request.json
        url = data.get('url')
        prediction = detect_phishing(url)
        return jsonify(prediction)
    except:
        data = request.json
        url = data.get('url')
        features = featureExtraction(url)
        input_features = features
        print(input_features)
        if (input_features.__len__() != 17):
            return {"status_code": 69, "message": "error"}

        return {"status_code": 200, "prediction": int(run_prediction(input_features[1:]))}


@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url')
    features = featureExtraction(url)
    input_features = features
    print(input_features)
    if (input_features.__len__() != 17):
        return {"status_code": 69, "message": "error"}

    return {"status_code": 200, "prediction": int(run_prediction(input_features[1:]))}


if __name__ == '__main__':
    app.run(debug=True)
