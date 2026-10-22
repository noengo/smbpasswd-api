function getToken() {
    // The token is in the URL fragment (https://host/#token): the browser never
    // sends the fragment to the server, so it can't leak in logs or Referer.
    return window.location.hash.length > 1 ? window.location.hash.slice(1) : "";
}

function disableForm() {
    $("input,button").prop("disabled", true);
}

function populateUsername(token) {
    function fail() {
        disableForm();
        Swal.fire({
            icon: 'error',
            title: 'Oops...',
            html: 'Invalid or expired link! <br />Contact your System Administrator.'
        });
    }

    $.ajax({
        url: "api/get_username",
        type: "POST",
        data: JSON.stringify({ "token": token }),
        contentType: "application/json; charset=UTF-8",
        processData: false,
        dataType: "json"
    }).done(function (data) {
        if (data && typeof data === "object" && data.hasOwnProperty("username")) {
            $("#username").val(data["username"]);
        } else {
            fail();
        }
    }).fail(function (data) {
        fail();
    });
}

(function () {
    var token = getToken();

    var check = function () {
        var equal = $("#password-check").val() == $("#password").val();
        $("#password-check-icon").attr('class', equal ? "fa fa-lock text-success" : "fa fa-unlock-alt text-danger");
        $("#password-check-msg").text(equal ? "OK" : "Mismatch").attr("class", "input-group-text text-" + (equal ? "success" : "danger"));
        $("#btn-submit").prop("disabled", !equal || !$("#password").val());
    };

    $("#btn-submit").click(function () {
        $("#btn-submit").prop("disabled", true);
        $.ajax({
            url: "api/set_password",
            type: "POST",
            data: JSON.stringify({ "token": token, "password": $("#password-check").val() }),
            contentType: "application/json; charset=UTF-8",
            processData: false,
            dataType: "json"
        }).done(function (data) {
            if (data && typeof data === "object" &&
                data.hasOwnProperty("status") && data["status"] == "OK") {
                $("#username,#password,#password-check").val("");
                disableForm();
                Swal.fire({
                    icon: 'success',
                    title: 'Done',
                    text: "User's password changed!"
                });
            } else {
                check();
            }
        }).fail(function (xhr) {
            if (xhr.status == 400) {
                // Token invalid, expired or already used
                disableForm();
                Swal.fire({
                    icon: 'error',
                    title: 'Oops...',
                    html: "Invalid or expired link. <br />Contact your System Administrator."
                });
            } else {
                // The link stays valid: the user can try another password
                check();
                Swal.fire({
                    icon: 'error',
                    title: 'Password not changed',
                    html: "The password was rejected. It may not meet the password policy " +
                          "(length, complexity, history). <br />Try another password or contact your System Administrator."
                });
            }
        });
    });

    $("#password").on("input keypress keyup keydown change", function () {
        var color = "", index = 0, msg = "";

        var pass = $(this).val();
        if(pass) {
            var score = zxcvbn(pass).score;

                 if (score == 0)              { color = "text-danger"; index = 0; msg = "Very weak"; }
            else if (score > 0 && score <= 1) { color = "text-warning"; index = 1; msg = "Weak"; }
            else if (score > 1 && score <= 2) { color = "text-info"; index = 2; msg = "Fair"; }
            else if (score > 2 && score <= 3) { color = "text-primary"; index = 3; msg = "Good"; }
            else if (score > 3)               { color = "text-success"; index = 4; msg = "Strong"; }
            else                              { color = ""; index = 0; msg = ""; }
        }

        $("#thermometer").attr('class', "fa fa-thermometer-" + index + " " + color);
        $("#thermometer-msg").text(msg).attr("class", "input-group-text " + color);
        check();
    });
    $("#password-check").on("input keypress keyup keydown change", check);

    $("#thermometer").attr('class', "fa fa-thermometer-0 text-danger");
    $("#thermometer-msg").text("").attr("class", "input-group-text text-danger");
    $("#password-check-icon").attr('class', "fa fa-lock text-success");
    $("#password-check-msg").attr("class", "input-group-text text-success").text("OK");

    if (token.length > 0)
        populateUsername(token);
    else {
        disableForm();
        Swal.fire({
            icon: 'error',
            title: 'Oops...',
            html: 'Invalid user. <br />Contact your System Administrator.'
        });
    }
    $("#password").focus();
})();
