// Sample Web Login using Angular-JS

var HOST = window.location.hostname;
var PORT = window.location.port;
var PROVIDER_URL = "http://"+HOST+":"+PORT+"/provider/";

var caronte_client = null;
CaronteClient(HOST, PORT,
	function (conn){ caronte_client = conn; },
	function () {} // no connection to Caronte
);

//register App with Angular
var crAuthApp = angular.module('crAuthApp', ["ngRoute"]);

//app route configuration
crAuthApp.config(function($routeProvider, $locationProvider){
	$locationProvider.hashPrefix('');
	$routeProvider.when('/', // startup controller
		{
			controller: "startupController",
			controllerAs: "ctx",
			templateUrl: "pages/none.html",
			resolve: {
				delay: function($q, $timeout) {
					var delay = $q.defer();
					$timeout(delay.resolve, 100);
					return delay.promise;
				}
			}
		}
	)
	.when('/main', // main page controller
		{
			controller: "crAuthController",
			controllerAs: "ctx",
			templateUrl: "pages/main.html"
		}
	)
	.when('/login', // login page controller
		{
			controller: "loginController",
			controllerAs: "ctx",
			templateUrl: "pages/login.html"
		}
	)
	.when('/register', // register page controller
		{
			controller: "registerController",
			controllerAs: "ctx",
			templateUrl: "pages/register.html"
		}
	);
});

// make sure CSRF Token is present in HTTP Headers or communication with Django server will fail
crAuthApp.config(['$httpProvider', function($httpProvider) {
	$httpProvider.defaults.xsrfCookieName = 'csrftoken';
	$httpProvider.defaults.xsrfHeaderName = 'X-CSRFToken';
	$httpProvider.defaults.withCredentials = true;
}]);

// startup controller
crAuthApp.controller("startupController", function($route, $window, $timeout){
	var ctx = this;
	if (caronte_client.isLoggedIn()){ // if logged in go to main page
		caronte_client.getUserDetails(function(user){
			$window.location.href = "#/main";
		});
	}
	else{ // go to login page
		$window.location.href = "#/login";
	}
});

// controller for main page
crAuthApp.controller("crAuthController", function($route, $window, $timeout){

	if (!caronte_client.isLoggedIn()){ // check if logged in
		$window.location.href = "#/login";
		return;
	}

	var ctx = this;
	ctx.user = caronte_client.user; // user details as given by Caronte
	ctx.ticket = ""; // success or error message in ticket verification
	ctx.old_pass = ""; // binding for old password field in user update form
	ctx.new_pass = ""; // binding for new password field in user update form
	ctx.name = ctx.user.name; // binding for user name field in user update form
	ctx.msg = ""; // binding for result message in user update form
	ctx.data = null; // binding for data from service provider
	ctx.caronte_id = caronte_client.caronte_id; // binding for caronte ID
	
	// callback for logout button
	ctx.logout = function(){
		var onLogout = function(){ // callback for caronte client library
			$window.location.href = "#/";
			$window.location.reload();
		}
		caronte_client.logout(onLogout, onLogout); // call caronte client library
	};
	
	// callback for update user button
	ctx.updateUser = function(){
		ctx.msg = "Updating...";
		// call caronte client library
		caronte_client.updateUser(ctx.name, ctx.old_pass, ctx.new_pass,
			function(){ // OK callback
				caronte_client.getUserDetails(function(user){ // update user details
					$timeout(function (){ctx.user=user;});
				});
				$timeout(function (){ // send GUI message
					ctx.password = "";
					ctx.msg = "Update done";
				});
			},
			function(){ // ERROR callback
				$timeout(function (){ctx.msg = "Unable to update user details";}); // send GUI message
			}
		);
	};
	
	// callback for validate ticket button
	ctx.validateTicket = function(){
		ctx.ticket = "";
		caronte_client.validateTicket( // call caronte client library
			function(){ // OK callback
				$timeout(function(){ctx.ticket = "Success!";}); // send GUI message
			},
			function(){ // ERROR callback
				$timeout(function(){ctx.ticket = "Error";}); // send GUI message
			}
		);
	};
	
	// callback for revalidate ticket button
	ctx.revalidateTicket = function(){
		ctx.ticket = "";
		caronte_client.revalidateTicket( // call caronte client library
			function(){ // OK callback
				$timeout(function(){ctx.ticket = "Success!";}); // send GUI message
			},
			function(){ // ERROR callback
				$timeout(function(){ctx.ticket = "Error";}); // send GUI message
			}
		);
	};
	
	// callback for invalidate ticket button
	ctx.invalidateTicket = function(){
		ctx.ticket = "";
		caronte_client.invalidateTicket( // call caronte client library
			function(){ // OK callback
				$timeout(function(){ctx.ticket = "Success!";}); // send GUI message
			},
			function(){ // ERROR callback
				$timeout(function(){ctx.ticket = "Error";}); // send GUI message
			}
		);
	};
	
	// callback for connect to service provider button
	ctx.connectServiceProvider = function(){
		var ticket = caronte_client.getTicket(); // get a valid ticket
		if (ticket != null){
			// build HTTP request for login
			var xhttp = new XMLHttpRequest();
			xhttp.onreadystatechange = function(){
				if (xhttp.readyState === 4 && xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText);
					if (res["status"] == "OK"){
						// set temporary session key for safe communication
						var my_service_provider = caronte_client.setOtherKey(res["key"]);
						// request data to service provider
						var xhttp2 = new XMLHttpRequest();
						xhttp2.onreadystatechange = function(){
							if (xhttp2.readyState === 4 && xhttp2.status === 200){
								var res = JSON.parse(xhttp2.responseText);
								// decrypt data from service provider
								$timeout(function (){
									ctx.data = caronte_client.decryptOther(my_service_provider, res["msg"]);
								});
							}
						}
						xhttp2.open("GET", PROVIDER_URL, true);
						xhttp2.send();
					}
					else{
						ctx.data = res["status"] + " - " + res["msg"];
					}
				}
			}
			// send HTTP request for login
			xhttp.open("POST", PROVIDER_URL, true);
			xhttp.send(JSON.stringify({"ticket":ticket})); // send ticket to authenticate
		}
	};
	
	ctx.validateTicket();
	
});

// controller for login page
crAuthApp.controller("loginController", function($route, $window, $timeout, $location, $scope){
	var ctx = this;
	ctx.email = "";
	ctx.password = "";
	ctx.msg = "";
	
	// callback for login button
	ctx.login = function(){
		ctx.msg = "Authenticating with server...";
		caronte_client.login(ctx.email, ctx.password, // call caronte client library
			function(){ $window.location.href = "#/"; }, // OK callback
			function(){ ctx.msg = "Unable to login, check email and password"; } // ERROR callback
		);
	};
	ctx.testlogin = function(){
		ctx.msg = "Authenticating with server...";
		caronte_client.login("test@caronte.com", "Caront3Te$t", // call caronte client library
			function(){ $window.location.href = "#/"; }, // OK callback
			function(){ ctx.msg = "Unable to login, check email and password"; } // ERROR callback
		);
	};
	
});

// controller for registration page
crAuthApp.controller("registerController", function($route, $window, $timeout){
	var ctx = this;
	ctx.name = "";
	ctx.email = "";
	ctx.password = "";
	ctx.password2 = "";
	ctx.secret = "";
	ctx.msg = "";
	
	// callback for register button
	ctx.register = function(){
		if (ctx.password != ctx.password2){
			ctx.msg = "Passwords do not match, check again";
			return;
		}
		ctx.msg = "Sending data to server...";
		caronte_client.register(ctx.name, ctx.email, ctx.password, ctx.secret, // call caronte client library
			function(){ $window.location.href = "#/login"; }, // OK callback
			function(){ ctx.msg = "Unable to register, user already exists? Try login"; } // ERROR callback
		);
	};
});
