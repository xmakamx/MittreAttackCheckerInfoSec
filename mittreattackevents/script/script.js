$( document ).ready(function() {	
	var table = $('#example').DataTable( {
		"ajax": "data.php",
		"bPaginate":true,
		"bProcessing": true,
		"pageLength": 5,
		"columns": [
			{ mData: 'ID' },
			{ mData: 'ID1' },
			{ mData: 'ID2' },
			{ mData: 'ID3' },
			{ mData: 'ID4' },
			{ mData: 'ID5' },
			{ mData: 'ID6' },
			{ mData: 'ID7' },
			{ mData: 'ID8' }
		]
	});	
	setInterval( function () {
		table.ajax.reload(null, false);
	}, 5000 );	
});