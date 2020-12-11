#pragma once
#include <QDialog>
#include <QGridLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QHBoxLayout>
#include <QTimer>
#include "arper.h"

class Dialog : public QDialog
{
    Q_OBJECT
public:
    Dialog(QWidget *parent = nullptr);
    ~Dialog();
private:
    static constexpr size_t IPV4_ADDR_BYTES = 4;
    static constexpr const char* const IPV4_DEFAULT_ADDR[Dialog::IPV4_ADDR_BYTES] {
        "192", "168", "1", "1",
    };
    QLineEdit* ipv4_inputs[Dialog::IPV4_ADDR_BYTES];
    QPushButton *get_mac;
    QHBoxLayout *ip_lay;
    QLabel *status;
    QGridLayout *main_lay;
    QTimer *status_timer; /// todo: use singleShot if no blurring
    ARPer arper;
private slots:
    void get_mac_clicked();
    void update_status_timer();
};
