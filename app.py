from flask import Flask,render_template,request
import pickle
app = Flask(__name__)


model = pickle.load(open('random_forest_model.pkl','rb'))



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']

   
    url_length = len(url)
    letter_counts = sum(c.isalpha() for c in url)
    digits_counts = sum(c.isdigit() for c in url)
    special_characters_count = sum(not c.isalnum() for c in url)
    shortend = 1 if len(url) < 20 else 0  
    abnormal_url = 1 if "http" not in url else 0
    secured_http = 1 if "https" in url else 0
    ip = 1 if any(part.isdigit() and int(part) < 256 for part in url.split('.')) else 0

    
    features = [[url_length, letter_counts, digits_counts, special_characters_count, shortend, abnormal_url, secured_http, ip]]
    prediction = model.predict(features)[0] 

    
    if prediction == 0:
        predicted_site_type = 'This site is safe to browse.'
    elif prediction == 1:
        predicted_site_type = 'This site is a suspicious site. Please do not enter any sensitive informa'
    elif prediction == 2:
        predicted_site_type = 'This site is a phishing site. Please do not enter any sensitive information.'
    elif prediction == 3:
        predicted_site_type = 'This site is a malicious site. Please do not enter any sensitive information.'
    else:
        predicted_site_type = 'unknown site type.'


    
    return render_template('index.html', url=url, predicted_site_type=predicted_site_type)


if __name__ == '__main__':
    app.run(debug=True)