var PROTOCOL = "http";
var HOST = window.location.hostname; //"5.196.67.102";
var PORT = window.location.port; //"8008";
var PROVIDER_URL = PROTOCOL+"://"+HOST+":"+PORT+"/provider/";

var caronte_client = CaronteClient(PROTOCOL, HOST, PORT);

//register App with Angular
var crAuthApp = angular.module('crAuthApp', ["ngRoute"]);

//app route configuration
crAuthApp.config(function($routeProvider, $locationProvider){
	$locationProvider.hashPrefix('');
	$routeProvider.when('/',
		{
			controller: "crAuthController",
			controllerAs: "ctx",
			templateUrl: "pages/main.html",
			resolve: {
				delay: function($q, $timeout) {
					var delay = $q.defer();
					$timeout(delay.resolve, 100);
					return delay.promise;
				}
			}
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

// controller for main page
crAuthApp.controller("crAuthController", function($route, $window, $timeout){
	var ctx = this;
	ctx.user = caronte_client.getUserDetails();
	ctx.ticket = caronte_client.validateTicket();
	ctx.old_pass = "";
	ctx.new_pass = "";
	ctx.name = "";
	ctx.msg = "";
	ctx.data = null;
	ctx.caronte_id = caronte_client.caronte_id;
	
	if (ctx.user == null || caronte_client.ticket == null){
		$window.location.href = "#/login";
		$window.location.reload();
	}
	else{
		ctx.name = ctx.user.name;
	}
	
	ctx.logout = function(){
		$timeout(function (){
			caronte_client.logout();
			$window.location.href = "#/";
			$window.location.reload();
		});
	};
	
	ctx.updateUser = function(){
		ctx.msg = "Updating...";
		$timeout(function (){
			caronte_client.updateUser(ctx.name, ctx.old_pass, ctx.new_pass);
			ctx.user = caronte_client.getUserDetails();
			ctx.password = "";
			ctx.msg = "Update done";
		});
	};
	
	ctx.validateTicket = function(){
		ctx.ticket = "";
		$timeout(function (){
			ctx.ticket = caronte_client.validateTicket();
		});
	};
	
	ctx.revalidateTicket = function(){
		ctx.ticket = "";
		$timeout(function (){
			ctx.ticket = caronte_client.revalidateTicket();
		});
	};
	
	ctx.invalidateTicket = function(){
		ctx.ticket = "";
		$timeout(function (){
			ctx.ticket = caronte_client.invalidateTicket();
		});
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
						caronte_client.setOtherKey("my_service_provider", res["key"]);
						
						// request data to service provider
						var xhttp = new XMLHttpRequest();
						xhttp.open("GET", PROVIDER_URL, false);
						xhttp.send();
						if (xhttp.readyState === 4 && xhttp.status === 200){
							var res = JSON.parse(xhttp.responseText);
							// decrypt data from service provider
							ctx.data = caronte_client.decryptOther("my_service_provider", res["msg"]);
						}
					}
				}
			}
		});
	};
	
});

// controller for login page
crAuthApp.controller("loginController", function($route, $window, $timeout){
	var ctx = this;
	ctx.email = "";
	ctx.password = "";
	ctx.msg = "";
	
	ctx.login = function(){
		ctx.msg = "Authenticating with server...";
		$timeout(function(){
			if(caronte_client.login(ctx.email, ctx.password)){
				$window.location.href = "#/";
			}
			else{
				ctx.msg = "Unable to login, check email and password";
			}
		});
	};
});

// controller for registration page
crAuthApp.controller("registerController", function($route, $window, $timeout){
	var ctx = this;
	ctx.name = "";
	ctx.email = "";
	ctx.password = "";
	ctx.msg = "";
	
	ctx.register = function(){
		ctx.msg = "Sending data to server...";
		$timeout(function (){
			if (caronte_client.register(ctx.name, ctx.email, ctx.password)){
				$window.location.href = "#/login";
				$window.location.reload();
			}
			else{
				ctx.msg = "Unable to register, user already exists? Try login";
			}
		});
	};
});
