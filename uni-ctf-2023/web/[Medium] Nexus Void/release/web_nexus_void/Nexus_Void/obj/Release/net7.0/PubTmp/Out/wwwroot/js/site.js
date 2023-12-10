// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

function addToFavourite(name, sellerName) {
    fetch("/Home/Wishlist", {
        "method": "POST",
        "Content-Type": "application/x-www-form-urlencoded",
        body: new URLSearchParams({
            'sellerName': sellerName,
            'name': name,
        })
    })
        .then((data) => {
            data.text().then(r => {

                di = document.getElementById("aler");
                mes = document.getElementById("mes");

                if (r === "Added") {
                    mes.textContent = "Product Added Succesfully";
                    di.style.display = "block";
                } else if (r === "Invalid") {
                    mes.textContent = "Invalid Product!";
                    di.style.display = "block";
                }
                else {
                    mes.textContent = "Product already exists";
                    di.style.display = "block";
                }

                setTimeout(() => {
                    mes.textContent = "";
                    di.style.display = "none";
                }, 3000)
            })
        })
}


function removeFromFavourite(name, sellerName) {
    fetch("/Home/WishlistRemove", {
        "method": "POST",
        "Content-Type": "application/x-www-form-urlencoded",
        body: new URLSearchParams({
            'sellerName': sellerName,
            'name': name,
        })
    })
        .then((data) => { window.location.reload() })
}