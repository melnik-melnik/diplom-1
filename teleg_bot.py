import telebot

bot = telebot.TeleBot('1773242870:AAElQwqqHAh8aSdd6mgmEqqjlbtAeNMhxJ8')
import db_query

# DnsTunnelBot, dns_tunnel_notify
# https://telegram.me/DnsTunnelBot
# chat.id = 150150396

def start():
    bot.polling(none_stop=True, interval=0)


def send1(chatid, msg):
    bot.send_message(chatid, msg)

chatid = ''

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, f'Я бот. Приятно познакомиться, {message.from_user.first_name}')
    bot.send_message(message.from_user.id, "Для начала работы введите пароль")


@bot.message_handler(content_types=['text'])
def get_text_messages(message):
    if message.text == "12345":
        chatid = message.from_user.id
        bot.reply_to(message, f'Этой твой chat_id: {chatid}')
        bot.send_message(chatid, "Добавь его через специально поле, и я буду оповещать тебя об инцидентах")
    else:
        bot.send_message(message.from_user.id, "Неверный пароль")
