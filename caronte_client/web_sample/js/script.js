var PROTOCOL = "http";
var HOST = window.location.hostname;
var PORT = window.location.port;
var PROVIDER_URL = PROTOCOL+"://"+HOST+":"+PORT+"/provider/";

var caronte_client = CaronteClient(PROTOCOL, HOST, PORT);

//register App with Angular
var crAuthApp = angular.module('crAuthApp', ["ngRoute"]);

//app route configuration
crAuthApp.config(function($routeProvider, $locationProvider){
	$locationProvider.hashPrefix('');
	$routeProvider.when('/',
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
	.when('/main',
		{
			controller: "crAuthController",
			controllerAs: "ctx",
			templateUrl: "pages/main.html"
		}
	)
	.when('/login',
		{
			controller: "loginController",
			controllerAs: "ctx",
			templateUrl: "pages/login.html"
		}
	)
	.when('/register',
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

crAuthApp.controller("startupController", function($route, $window, $timeout){
	var ctx = this;
	if (caronte_client.isLoggedIn()){
		caronte_client.getUserDetails(function(user){
			$window.location.href = "#/main";
		});
	}
	else{
		$window.location.href = "#/login";
	}
});

// controller for main page
crAuthApp.controller("crAuthController", function($route, $window, $timeout){

	if (!caronte_client.isLoggedIn()){
		$window.location.href = "#/login";
		return;
	}

	var ctx = this;
	ctx.user = caronte_client.user;
	ctx.ticket = "";
	ctx.old_pass = "";
	ctx.new_pass = "";
	ctx.name = ctx.user.name;
	ctx.msg = "";
	ctx.data = null;
	ctx.caronte_id = caronte_client.caronte_id;
	
	ctx.logout = function(){
		var onLogout = function(){
			$window.location.href = "#/";
			$window.location.reload();
		}
		caronte_client.logout(onLogout, onLogout);
	};
	
	ctx.updateUser = function(){
		ctx.msg = "Updating...";
		caronte_client.updateUser(ctx.name, ctx.old_pass, ctx.new_pass,
			function(){
				caronte_client.getUserDetails(function(user){
					$timeout(function (){ctx.user=user;});
				});
				$timeout(function (){
					ctx.password = "";
					ctx.msg = "Update done";
				});
			},
			function(){
				$timeout(function (){ctx.msg = "Unable to update user details";});
			}
		);
	};
	
	ctx.validateTicket = function(){
		ctx.ticket = "";
		caronte_client.validateTicket(
			function(){
				$timeout(function(){ctx.ticket = "Success!";});
			},
			function(){
				$timeout(function(){ctx.ticket = "Error";});
			}
		);
	};
	
	ctx.revalidateTicket = function(){
		ctx.ticket = "";
		caronte_client.revalidateTicket(
			function(){
				$timeout(function(){ctx.ticket = "Success!";});
			},
			function(){
				$timeout(function(){ctx.ticket = "Error";});
			}
		);
	};
	
	ctx.invalidateTicket = function(){
		ctx.ticket = "";
		caronte_client.invalidateTicket(
			function(){
				$timeout(function(){ctx.ticket = "Success!";});
			},
			function(){
				$timeout(function(){ctx.ticket = "Error";});
			}
		);
	};
	
	ctx.connectServiceProvider = function(){
		$timeout(function (){
			var ticket = caronte_client.getTicket(); // get a valid ticket
			if (ticket != null){
				// login
				var xhttp = new XMLHttpRequest();
				xhttp.open("POST", PROVIDER_URL, false);
				xhttp.send(JSON.stringify({"ticket":ticket})); // send ticket to authenticate
				if (xhttp.readyState === 4 && xhttp.status === 200){
					var res = JSON.parse(xhttp.responseText);
					if (res["status"] == "OK"){
						// set temporary session key for safe communication
						var my_service_provider = caronte_client.setOtherKey(res["key"]);
						
						// request data to service provider
						var xhttp = new XMLHttpRequest();
						xhttp.open("GET", PROVIDER_URL, false);
						xhttp.send();
						if (xhttp.readyState === 4 && xhttp.status === 200){
							var res = JSON.parse(xhttp.responseText);
							// decrypt data from service provider
							ctx.data = caronte_client.decryptOther(my_service_provider, res["msg"]);
						}
					}
				}
			}
		});
	};
	
	ctx.validateTicket();
	
	/*
	caronte_client.getUserDetails(function(user){
		ctx.user=user;
	});
	*/
	
});

// controller for login page
crAuthApp.controller("loginController", function($route, $window, $timeout, $location, $scope){
	var ctx = this;
	ctx.email = "";
	ctx.password = "";
	ctx.msg = "";
	
	ctx.login = function(){
		ctx.msg = "Authenticating with server...";
		caronte_client.login(ctx.email, ctx.password,
			function(){ $window.location.href = "#/"; },
			function(){ ctx.msg = "Unable to login, check email and password"; }
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
	
	ctx.register = function(){
		if (ctx.password != ctx.password2){
			ctx.msg = "Passwords do not match, check again";
			return;
		}
		ctx.msg = "Sending data to server...";
		caronte_client.register(ctx.name, ctx.email, ctx.password, ctx.secret,
			function(){ $window.location.href = "#/login"; },
			function(){ ctx.msg = "Unable to register, user already exists? Try login"; }
		);
	};
});
