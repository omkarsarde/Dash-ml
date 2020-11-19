from flask import Flask, request, render_template, jsonify, redirect
import socket
import pickle
import math
from ipwhois import IPWhois
import pandas as pd
from bokeh.io import output_file, show
from bokeh.embed import components
from bokeh.models import (
    HoverTool, ColumnDataSource, Legend, LegendItem
)
from bokeh.plotting import figure

"""
Authors: Omkar Sarde, Sharwari Salunkhe, Amit Rokade
"""

app = Flask(__name__)
app.config["DEBUG"] = True


def site_status(input):
    https_status, ip, socket_status, lookup_status, reflected_status = [False for i in range(5)]
    obj = None
    if "https://" in input:
        https_status = True
        site = input.split('//')[1]
        site = site.split("/")[0]
        ip, socket_status, lookup_status, reflected_status, obj = validate_input(site)
    else:
        https_status = False
        site = input.split("/")[0]
        ip, socket_status, lookup_status, reflected_status, obj = validate_input(site)
    return https_status, ip, socket_status, lookup_status, reflected_status, obj


def validate_input(site):
    ip, socket_status, lookup_status, reflected_status = [False for i in range(4)]
    obj, ip_val = None, None
    try:
        ip_val = socket.gethostbyname(site)
        socket_status = True
        try:
            obj = IPWhois(ip_val)
            lookup_status = True
            obj = obj.lookup_whois()
            if obj['asn_description'] == None:
                reflected_status = True
            else:
                reflected_status = False
        except:
            print('Lookup error https')
            lookup_status = False
    except:
        print('Socket error non https')
        socket_status = False
        reflected_status = True
        lookup_status = False

    return ip_val, socket_status, lookup_status, reflected_status, obj


def logic(prediction, site):
    labels = {0: 'Benign Website', 1: 'Defacement Website', 2: 'Malware Website', 3: 'Phishing Website',
              4: 'Spam Website'}
    https_status, ip_val, socket_status, lookup_status, reflected_status, obj = site_status(site)
    prediction = labels[prediction]
    data_dict = {'Model Prediction': [None, 30], 'Https Status': [None, 10], 'IP Value': [None, 10],
                 'Socket Status': [None, 15], 'Lookup Status': [None, 10],
                 'Trust Status': [None, 25]}
    if prediction == "Benign Website":
        data_dict["Model Prediction"][0] = 30
    elif prediction == "Defacement Website":
        data_dict['Model Prediction'][0] = 20
    elif prediction == "Malware Website" or prediction == "Phishing Website":
        data_dict['Model Prediction'][0] = 0
    data_dict = logic_helper(data_dict, https_status, 'Https Status', False, 0, 10)
    data_dict = logic_helper(data_dict, ip_val, 'IP Value', None, 0, 10)
    data_dict = logic_helper(data_dict, socket_status, 'Socket Status', False, 0, 15)
    data_dict = logic_helper(data_dict, lookup_status, 'Lookup Status', False, 0, 10)
    data_dict = logic_helper(data_dict, reflected_status, 'Trust Status', True, 0, 25)
    script, div = plot_pie_chart(data_dict, site)
    return prediction, obj, data_dict, script, div


def logic_helper(data, under_test, under_test_str, condition, score_zero, score_full):
    if under_test == condition:
        data[under_test_str][0] = score_zero
    else:
        data[under_test_str][0] = score_full
    return data


def plot_pie_chart(data_dict, site):
    sectors = list(data_dict.keys())
    values_base = list(data_dict.values())
    values_act = [str(percent[0]) + "/" + str(percent[1]) for percent in values_base]
    radians = [math.radians((percent[1] / 100) * 360) for percent in values_base]
    color = ["#abdda4" if percent[0] > 0 else "#d7191c" for percent in values_base]

    # starting angle values
    start_angle = [math.radians(0)]
    prev = start_angle[0]
    for i in radians[:-1]:
        start_angle.append(i + prev)
        prev = i + prev
    # ending angle values
    end_angle = start_angle[1:] + [math.radians(0)]

    source = ColumnDataSource(
        dict(starts=start_angle, ends=end_angle, labels=sectors, colors=color, amounts=values_act))

    plot = figure(plot_height=600, title=f"WebSite Stats for: {site}",
                  background_fill_color='lightgrey')

    hover = HoverTool(
        tooltips=[
            ('Measure', '@labels'),
            ('Score', '@amounts')
        ]
    )
    plot.add_tools(hover)

    r = plot.wedge(0, 0, radius=1, start_angle='starts', end_angle='ends', line_color='black', color='colors',
                   source=source)

    legend = Legend(items=[LegendItem(label=dict(field="labels"), renderers=[r])], location=(0, 0))
    plot.add_layout(legend, 'right')
    scripts, div = components(plot)
    return scripts, div


@app.route('/', methods=['GET'])
def home():
    """
    Basic homepage
    :return: html
    """
    return render_template("index.html")


@app.route('/predict', methods=['POST'])
def predict():
    """
    Takes user input, runs pickled model on it and renders output
    :return:
    """
    file = open(r'./static/vectorizer.pickle', 'rb')
    vectorizer = pickle.load(file)
    file.close()
    file = open(r'./static/transfomer.pickle', 'rb')
    transfomer = pickle.load(file)
    file.close()
    file = open(r'./static/model.pickle', 'rb')
    model = pickle.load(file)
    file.close()
    site = [x for x in request.form.values()][0]

    input_val = [site]
    input_val = vectorizer.transform(input_val)
    input_val = transfomer.transform(input_val)
    prediction = model.predict(input_val)[0]
    prediction, obj, data_dict, script, div = logic(prediction, site)
    score = list(data_dict.values())
    score = sum(n for n, _ in score)
    if obj == None:
        obj = {'Could Not Connect To Site': 'Check URL, MOST LIKELY UNTRUSTWORTHY'}
    return render_template('prediction.html', pred=f'{prediction}', input_val=f'{site}', score=score, information=obj,
                           measures=data_dict, script=script, div=div)


@app.route('/api', methods=['GET'])
def api():
    if 'web' in request.args:
        file = open(r'./static/vectorizer.pickle', 'rb')
        vectorizer = pickle.load(file)
        file.close()
        file = open(r'./static/transfomer.pickle', 'rb')
        transfomer = pickle.load(file)
        file.close()
        file = open(r'./static/model.pickle', 'rb')
        model = pickle.load(file)
        file.close()

        site = request.args['web']
        input_val = vectorizer.transform([site])
        input_val = transfomer.transform(input_val)
        prediction = model.predict(input_val)[0]
        prediction, obj, data_dict, script, div = logic(prediction, site)
        score = list(data_dict.values())
        score = sum(n for n, _ in score)
        if obj == None:
            obj = {'Could Not Connect To Site': 'Check URL, MOST LIKELY UNTRUSTWORTHY'}
        pred = {'Website': site, 'Trust Score': str(score) + " / 100",
                'Model Prediction': prediction, 'Site Details': obj, 'Trust Measures': data_dict,
                "Source Data Reference": "USCIX 2016 Dataset"}
    else:
        return "Error: Incorrect API FORMAT. Reference format application/api?web=google.com"
    return jsonify(pred)


if __name__ == '__main__':
    """
    main function
    """
    app.run(debug=False)
