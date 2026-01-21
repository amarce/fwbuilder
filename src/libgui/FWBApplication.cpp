/*

                          Firewall Builder

                 Copyright (C) 2010 NetCitadel, LLC

  Author:  Vadim Kurland     vadim@fwbuilder.org

  $Id$

  This program is free software which we release under the GNU General Public
  License. You may redistribute and/or modify this program under the terms
  of that license as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  To get a copy of the GNU General Public License, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/


#include "global.h"
#include "FWBSettings.h"
#include "FWBApplication.h"
#include "FWWindow.h"

#include "fwbuilder/FWException.h"

#include <QtDebug>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMessageBox>
#include <QMetaEnum>
#include <QStandardPaths>
#include <QTextStream>
#include <QTimer>
#include <typeinfo>

using namespace libfwbuilder;
using namespace std;

namespace
{
QString eventTypeDescription(const QEvent *event)
{
    if (!event)
        return QString("Unknown (no event)");

    QMetaEnum meta_enum = QMetaEnum::fromType<QEvent::Type>();
    const char *key = meta_enum.valueToKey(event->type());
    if (key)
        return QString("%1 (%2)").arg(key).arg(static_cast<int>(event->type()));

    return QString("Custom (%1)").arg(static_cast<int>(event->type()));
}

QString receiverDescription(const QObject *receiver)
{
    if (!receiver)
        return QString("Unknown (no receiver)");

    QString description = QString("%1").arg(receiver->metaObject()->className());
    if (!receiver->objectName().isEmpty())
        description += QString(" [objectName=%1]").arg(receiver->objectName());
    return description;
}

QString errorLogPath()
{
    QString log_dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (log_dir.isEmpty())
        log_dir = QDir::homePath();
    QDir().mkpath(log_dir);
    return QDir(log_dir).filePath("fwbuilder-error.log");
}

void logUnhandledException(const QString &exception_type,
                           const QString &message,
                           const QObject *receiver,
                           const QEvent *event)
{
    QFile file(errorLogPath());
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text))
        return;

    QTextStream out(&file);
    out << "==== Unhandled exception ====" << "\n";
    out << "Timestamp: " << QDateTime::currentDateTime().toString(Qt::ISODateWithMs) << "\n";
    out << "Application PID: " << QCoreApplication::applicationPid() << "\n";
    out << "Exception type: " << exception_type << "\n";
    out << "Exception message: " << message << "\n";
    out << "Receiver: " << receiverDescription(receiver) << "\n";
    out << "Event: " << eventTypeDescription(event) << "\n";
    if (QWidget *active = QApplication::activeWindow())
    {
        out << "Active window: " << active->metaObject()->className();
        if (!active->objectName().isEmpty())
            out << " [objectName=" << active->objectName() << "]";
        if (!active->windowTitle().isEmpty())
            out << " [title=" << active->windowTitle() << "]";
        out << "\n";
    }
    out << "=============================" << "\n";
    out.flush();
}
}

void FWBApplication::quit()
{
    if (fwbdebug) qDebug() << "FWBApplication::quit()";
    timeout = 0;

    if (mw->isVisible()) mw->hide();

    if (st->getCheckUpdates())
    {
        QTimer::singleShot(100, this, SLOT(delayedQuit()));
    } else
        delayedQuit();
}

void FWBApplication::delayedQuit()
{
    if (fwbdebug) qDebug() << "FWBApplication::delayedQuit()";

    QApplication::quit();
}

bool FWBApplication::notify(QObject *receiver, QEvent *event)
{
    static bool handling_exception = false;

    try
    {
        return QApplication::notify(receiver, event);
    } catch (const libfwbuilder::FWException &ex)
    {
        QString message = QString::fromStdString(ex.toString());
        logUnhandledException("libfwbuilder::FWException", message, receiver, event);
        if (!handling_exception)
        {
            handling_exception = true;
            QMessageBox::critical(
                QApplication::activeWindow(),
                tr("Firewall Builder"),
                tr("The application encountered an internal error and needs to close.\n"
                   "Please save your work if possible, then restart the application.\n"
                   "Details were written to:\n%1").arg(errorLogPath()));
            QTimer::singleShot(0, this, SLOT(quit()));
        }
    } catch (const std::string &s) {
        QString message = QString::fromStdString(s);
        logUnhandledException("std::string", message, receiver, event);
        if (!handling_exception)
        {
            handling_exception = true;
            QMessageBox::critical(
                QApplication::activeWindow(),
                tr("Firewall Builder"),
                tr("The application encountered an internal error and needs to close.\n"
                   "Please save your work if possible, then restart the application.\n"
                   "Details were written to:\n%1").arg(errorLogPath()));
            QTimer::singleShot(0, this, SLOT(quit()));
        }
    } catch (const std::exception &ex) {
        QString message = QString::fromUtf8(ex.what());
        logUnhandledException(typeid(ex).name(), message, receiver, event);
        if (!handling_exception)
        {
            handling_exception = true;
            QMessageBox::critical(
                QApplication::activeWindow(),
                tr("Firewall Builder"),
                tr("The application encountered an internal error and needs to close.\n"
                   "Please save your work if possible, then restart the application.\n"
                   "Details were written to:\n%1").arg(errorLogPath()));
            QTimer::singleShot(0, this, SLOT(quit()));
        }
    }
    catch (...) {
        logUnhandledException("unknown", "Caught unsupported exception", receiver, event);
        if (!handling_exception)
        {
            handling_exception = true;
            QMessageBox::critical(
                QApplication::activeWindow(),
                tr("Firewall Builder"),
                tr("The application encountered an internal error and needs to close.\n"
                   "Please save your work if possible, then restart the application.\n"
                   "Details were written to:\n%1").arg(errorLogPath()));
            QTimer::singleShot(0, this, SLOT(quit()));
        }
    }
    return false;
}
