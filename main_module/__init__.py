import logging
from main_module import sniffer, session_pkt
from main_module.session_pkt import Notification

sniff = sniffer.Sniffer('default.cfg')
ses = session_pkt.Session()

ses.add_notificator(Notification.on_telegram_bot)


log_level = levels = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}

#logger = logging.getLogger('Analyze log')
#logger.setLevel(log_level[config['DEFAULT']['LOG_LEVEL']])