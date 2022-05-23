#pragma once
#include "PacketItem.h"
#include <QAbstractTableModel>

class PacketTableViewModel: public QAbstractTableModel
{
public:
	PacketTableViewModel(QObject* parent = nullptr);
	int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
	QVariant headerData(int section, Qt::Orientation orientation, int role) const;

	void insertItem(PacketItem pi);
	void clearModel();

	PacketItem getItem(int index) {
		return packetList[index];
	}

private:
	std::vector<PacketItem> packetList;
	
};
