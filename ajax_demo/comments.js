$(document).ready(function(){ 
	$('#commentForm').on('submit', function(event){
		event.preventDefault();								// chan submit mac dinh cua form de su dung submid cua js
		var formData = $(this).serialize();					// chuoi hoa data tren form thanh keyvalue de gui di
		$.ajax({											// truyen vao phuong thuc ajax doi tuong {thuoc_tinh}
			url: "comments.php",							// url = action
			method: "POST",									// method = method
			data: formData,									// data tu form
			dataType: "JSON",								// kieu data JSON (la 1 doi tuong)
			success:function(response) {					// 
				if(!response.error) {
					$('#commentForm')[0].reset();
					$('#commentId').val('0');
					$('#message').html(response.message);
					showComments();
				} else if(response.error){
					$('#message').html(response.message);
				}
			}
		})
	});	
	
	function showComments() {
		$.ajax({
			url:"show_comments.php",
			method:"POST",
			success:function(response) {
				$('#showComments').html(response);
			}
		})
	}
});


