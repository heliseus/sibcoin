#include "tableoffersview.h"
#include "convertdata.h"

TableOffersView::TableOffersView(DexDB *db, const TypeOffer &type, QDialog *parent) : TableOffersDialog(db, new OfferModelView, 3, parent), type(type)
{
    details = new OfferDetailsView(db, this);

    tableView->setColumnWidth(0, 150);
    tableView->setColumnWidth(1, 150);
    tableView->setColumnWidth(2, 150);
    tableView->setColumnWidth(3, 150);

    columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(tableView, 120, 23);

    updateData();
}

TableOffersView::~TableOffersView()
{
}

void TableOffersView::updateData()
{
    QList<QtOfferInfo> offers;
    if (type == Buy) {
        offers = ConvertData::toListQtOfferInfo(db->getOffersBuy());
    } else {
        offers = ConvertData::toListQtOfferInfo(db->getOffersSell());
    }

    pModel->setOffers(offers);

    init();
}

void TableOffersView::clickedButton(const int &index)
{
    QtOfferInfo info = pModel->offerInfo(index);
    details->setOfferInfo(info);
    details->show();
}

void TableOffersView::updateTables(const TypeTable &table, const TypeTableOperation &operation, const StatusTableOperation &status)
{
    if (type == Buy) {
        if (table == OffersBuy && (operation == Add || operation == Edit) && status == Ok) {
            updateData();
            Q_EMIT dataChanged();
        }
    } else if (type == Sell) {
        if (table == OffersSell && (operation == Add || operation == Edit) && status == Ok) {
            updateData();
            Q_EMIT dataChanged();
        }
    }
}
