<?php
namespace Torinit\awscognito\Providers;

use App\Auth\CognitoGuard;
use torinit\awscognito\cognito\CognitoClient;
use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\Application;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;

class CognitoAuthServiceProvider extends ServiceProvider
{
    public function boot()
    {       
        $this->publishes([
        __DIR__.'/../config/cognito.php' => config_path('cognito.php'),
        ], 'cognito');
        
        $this->app->singleton(CognitoClient::class, function (Application $app) {
            $config = [
                'credentials' => config('cognito.credentials'),
                'region'      => config('cognito.region'),
                'version'     => config('cognito.version')
            ];
            return new CognitoClient(
                new CognitoIdentityProviderClient($config),
                config('cognito.aws_cognito_client_id'),
                config('cognito.aws_cognito_client_secret'),
                config('cognito.aws_cognito_user_pool_id')
            );
        });
    }

    public function register()
    {
        
    }
}
