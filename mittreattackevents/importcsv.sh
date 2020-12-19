cd /directory
date=$(date '+%Y-%m-%d')
hour=$(date '+%H')
echo $date
echo $hour 
directory_name=$date
if [ -d $directory_name ]
then
		echo "Directory already exists"
	else
		mkdir $directory_name
fi
cd $directory_name
subdirectory_name=$hour
if [ -d $subdirectory_name ]
then
		echo "SubDirectory already exists"
	else
		mkdir $subdirectory_name
fi

for file in /direcotry/mittreattack/*.csv
	do echo "Importing file $file"
	echo $file 
		`mysql --user=root --password=[PASSWORD] MittreAttackChecker	<<-EOF
		LOAD DATA LOCAL INFILE '$file'
		IGNORE
		INTO TABLE ThreatData
		FIELDS TERMINATED BY ','
		ENCLOSED BY '"'
		ESCAPED BY ''
		LINES TERMINATED BY '\r\n'
		IGNORE 1 LINES
		(ID1, ID2, ID3, ID4, ID5, ID6, ID7, ID8);
		EOF`
	echo "Completed importing $file"
	mv $file /directory/mittreattack/archive/$directory_name/$subdirectory_name
done
