import datetime
import json
from random import randrange
from flask import render_template, request, url_for, redirect, make_response, session
import db_con
import db_query
import threading
import platform
import psutil
from main_module import pkt_parse, learn, sniff, ses
import os
from app import app
import teleg_bot


# ------------------------------------------------------------------#
#               Login page                                          #
# ------------------------------------------------------------------#

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        msg = ''
        return render_template('login.html', msg=msg)
    if request.method == 'POST':
        user = request.form["username"]
        pwd = request.form["password"]
        login_user = db_con.db_login.find_one({'login': user})
        if login_user:
            if pwd == login_user['pass']:
                session['login'] = request.form['username']
                # if bcrypt.hashpw(request.form['password'].encode('utf-8'), login_user['pass'].encode('utf-8')) == login_user['pass'].encode('utf-8'):
                return redirect(url_for('home'))
        msg = 'Неверная комбинация логин/пароль'
        return render_template('login.html', msg=msg)


@app.route('/delete_session', methods=['POST', 'GET'])
def delete_session():
    if request.method == 'POST':
        session.pop('login', None)  # удаление данных о посещениях
        return redirect(url_for('login'))


# ------------------------------------------------------------------#
#               Home page                                           #
# ------------------------------------------------------------------#

@app.route('/')
@app.route("/home", methods=['GET', 'POST'])
def home():
    if 'login' in session:
        res_last_ses = db_query.last_session_diagrams()
        msg = 'Для отображения выберите временной интервал'
        if request.method == 'POST':  # Вывести весь список

            str_to_date_start = datetime.datetime.strptime(request.form.get('start_date'), '%Y-%m-%dT%H:%M')
            str_to_date_end = datetime.datetime.strptime(request.form.get('end_date'), '%Y-%m-%dT%H:%M')

            res_timeline = db_query.timeline_diagrams(str_to_date_start, str_to_date_end)
            if res_timeline is not None and res_timeline != '':
                msg = 'Инофрмация за выбранное время, от ' + str(str_to_date_start) + ' до ' + str(str_to_date_end)
                return render_template('home.html', out=res_last_ses, pkt_data=res_last_ses[0],
                                       subdmn_data=res_last_ses[1],
                                       timeline_pkt_data=res_timeline[0], timeline_subdmn_data=res_timeline[1], msg=msg)
            else:
                msg = 'Некорректная дата!'
        return render_template('home.html', out=res_last_ses, pkt_data=res_last_ses[0], subdmn_data=res_last_ses[1],
                               msg=msg)
    else:
        return redirect(url_for('home'))


@app.route('/get_data', methods=['GET', 'POST'])
def get_data():
    data = [randrange(10), "ip_addr"]
    print(data)
    response = make_response(json.dumps(data))
    print(data)
    response.content_type = 'application/json'
    print(response)
    return response


# ------------------------------------------------------------------#
#               View traffic page                                   #
# ------------------------------------------------------------------#
'''
d = datetime.datetime(2009, 11, 12, 12)
for post in posts.find({"date": {"$lt": d}}).sort("author"):
...   pprint.pprint(post)
'''


@app.route("/traffic", methods=['GET', 'POST'])
def traffic():
    if 'login' in session:
        res = db_query.output_susp_traffic()
        if request.method == 'GET':  # Вывести весь список
            return render_template('traffic.html', traffic_list=res)

        if request.method == 'POST':  # Вывести результат поиска
            get_text_request = request.form.get('search_name')
            get_date_request = request.form.get('date_traffic')
            if get_text_request is not None and get_text_request != '':
                output_request = db_query.search_traffic(get_text_request)
                return render_template('traffic.html', traffic_list=output_request)
            # if get_date_request is not None and get_date_request != '': будет поиск по дате
            else:
                return redirect(url_for('traffic'))
    else:
        return redirect(url_for('login'))


# ------------------------------------------------------------------#
#               White list page                                     #
# ------------------------------------------------------------------#

@app.route("/white_list", methods=['GET', 'POST'])
def white_list():
    if 'login' in session:
        if request.method == 'GET':  # Вывести весь список
            output_request = db_query.find_white_list()
            return render_template('white_list.html', white_list=output_request)
        if request.method == 'POST':  # Вывести результат поиска
            get_request = request.form.get('search_name')
            if get_request != '':
                output_request = db_query.search_white_list(get_request)
                return render_template('white_list.html', white_list=output_request)
            else:
                return redirect(url_for('white_list'))
    else:
        return redirect(url_for('login'))


@app.route("/white_list/insert", methods=['GET', 'POST'])
def white_list_insert():  # Добавление домена
    if request.method == 'POST':
        get_request = request.form.get('name')
        if get_request != '':
            db_query.insert_white_list(get_request)
            return redirect(url_for('white_list'))
        else:
            return redirect(url_for('white_list'))


@app.route("/white_list/del/<id>")
def white_list_del(id):  # Удалить выбранный по индексу
    db_query.delete_white_list(id)
    return redirect(url_for('white_list'))


# ------------------------------------------------------------------#
#               Model fit page                                      #
# ------------------------------------------------------------------#

'''
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
'''


def get_adapter_names():
    print('os', platform.system())
    if platform.system() == 'Windows':
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        available_networks = []
        for intface, addr_list in addresses.items():
            if any(getattr(addr, 'address').startswith("169.254") for addr in addr_list):
                continue
            elif intface in stats and getattr(stats[intface], "isup"):
                available_networks.append(intface)
        return available_networks
    if platform.system() == 'Linux':
        return 'linux'


@app.route("/model_fit", methods=['GET', 'POST'])
def model_fit():
    if 'login' in session:
        return render_template('model_fit.html', select_adapter=get_adapter_names())
    else:
        return redirect(url_for('login'))


@app.route("/sniff_start", methods=['GET', 'POST'])
def sniff_start():
    th1 = threading.Thread(target=sniff.run_capture, daemon=True)
    th2 = threading.Thread(target=ses.start, daemon=True)

    th3 = threading.Thread(target=teleg_bot.start, daemon=True)
    th3.start()

    if not th1.is_alive():
        th1.start()

    if not th2.is_alive():
        th2.start()

    return redirect(url_for('model_fit'))


@app.route("/sniff_stop", methods=['GET', 'POST'])
def sniff_stop():
    sniff.stop_capture()
    ses.stop()
    return redirect(url_for('model_fit'))


@app.route("/model_fit_settings", methods=['GET', 'POST'])
def model_fit_settings():
    if request.method == 'POST':

        get_select_log = request.form.get('select_log')
        if get_select_log is not None and get_select_log != '':
            print('log ', get_select_log)

        get_select_adapter = request.form.get('select_adapter')
        if get_select_adapter is not None and get_select_adapter != '':
            print('adapter ', get_select_adapter)

        # изменить конфиг
        if get_select_adapter is not None and get_select_adapter != '' and get_select_log is not None and get_select_log != '':
            f = open('default.cfg', 'w')
            f.write('[DEFAULT]\nLOG_LEVEL = ' + get_select_log.upper() + '\nINTERFACE = ' + get_select_adapter)
            f.close()

    return redirect(url_for('model_fit'))


def_path = 'app/static/files/'


@app.route("/model_fit_upload", methods=['GET', 'POST'])
def model_fit_upload():
    file = request.files['file']
    if file:
        filename = file.filename
        file.save(os.path.join(def_path, filename))
        path_file = (def_path + filename)
        res_pcap_to_df = pkt_parse.parse_pcap_to_df(path_file, 0)
        mal_traffic = './mal_traf.csv'

        th4 = threading.Thread(target=learn.create_model, args=(res_pcap_to_df, mal_traffic), daemon=True)
        th4.start()

        return redirect(url_for('model_fit'))


@app.route("/insert_chat_id", methods=['GET', 'POST'])
def insert_chat_id():
    if request.method == 'POST':  # Вывести результат поиска
        get_chat_id = request.form.get('chat_id')
        db_query.insert_chat_id(get_chat_id)
    return redirect(url_for('model_fit'))
