#include "dialog.h"
#include <QClipboard>
#include <QApplication>
#include <string>
#include <future>

Dialog::Dialog(QWidget *parent)
    : QDialog(parent), arper()
{
    static constexpr QSize window_size(400, 100);
    static constexpr QSize input_size(35, 30);
    static constexpr QSize get_mac_size(100, 30);
    static constexpr QSize status_size(300, 30);

    this->setFixedSize(window_size);
    this->main_lay = new QGridLayout();
    this->ip_lay = new QHBoxLayout();
    for (size_t i = 0; i < Dialog::IPV4_ADDR_BYTES; ++i) {
        this->ipv4_inputs[i] = new QLineEdit(Dialog::IPV4_DEFAULT_ADDR[i]);
        this->ipv4_inputs[i]->setFixedSize(input_size);
        this->ip_lay->addWidget(this->ipv4_inputs[i]);
    }
    this->get_mac = new QPushButton("get MAC");
        this->get_mac->setFixedSize(get_mac_size);
        this->ip_lay->addWidget(this->get_mac);

    this->main_lay->addLayout(this->ip_lay, 0, 0, 1, Qt::AlignCenter);
    this->status = new QLabel("ready");
        this->status->setFixedSize(status_size);

    this->main_lay->addWidget(this->status, 1, 0, 1, 1 );


    this->setLayout(main_lay);

    this->status_timer = new QTimer();

    connect(this->get_mac, SIGNAL(clicked()),
            this, SLOT(get_mac_clicked()));
    connect(this->status_timer, SIGNAL(timeout()),
            this, SLOT(update_status_timer()));
}

void Dialog::get_mac_clicked()
{
    ARP_res_t res;
    QClipboard *clipboard = QApplication::clipboard();
    this->status->setText("in progress");
    for (size_t i = 0; i < Dialog::IPV4_ADDR_BYTES; ++i) {
        res.ip += this->ipv4_inputs[i]->text().toStdString();
        if (i < Dialog::IPV4_ADDR_BYTES - 1) {
            res.ip += ".";
        }
    }
    auto ifaces = this->arper.get_ifaces();
    for (const auto& iface: ifaces) {
        std::cout << iface << std::endl;
        this->arper.set_ifname(iface);
        if(this->arper.probe(res) == 0) {
            this->status->setText(QString("copied to clipboard: ") +
                                  QString(res.mac.c_str()));
            this->status_timer->start(1000);
            clipboard->setText(res.mac.c_str());
            return;
        }
    }
    this->status->setText("failed to find MAC");
}

void Dialog::update_status_timer()
{
    this->status->setText("ready");
    this->status_timer->stop();
}

Dialog::~Dialog()
{
}

