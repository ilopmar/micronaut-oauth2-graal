package test.github.oauth;

import io.micronaut.http.*;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.oauth2.client.OauthClient;
import io.micronaut.security.oauth2.url.OauthRouteUrlBuilder;
import org.reactivestreams.Publisher;

import javax.inject.Named;
import javax.inject.Singleton;
import java.util.*;

@Singleton
@Named("twitter")
public class TwitterOauthClient implements OauthClient {

    private static final String PARAM_TOKEN = "oauth_token";
    private static final String PARAM_TOKEN_SECRET = "oauth_token_secret";
    private static final String PARAM_VERIFIER = "oauth_verifier";
    private static final String PARAM_CALLBACK_CONF = "oauth_callback_confirmed";

    private final TwitterClient twitterClient;
    private final OauthRouteUrlBuilder routeUrlBuilder;

    public TwitterOauthClient(TwitterClient twitterClient,
                              OauthRouteUrlBuilder routeUrlBuilder) {
        this.twitterClient = twitterClient;
        this.routeUrlBuilder = routeUrlBuilder;
    }

    @Override
    public String getName() {
        return "twitter";
    }

    @Override
    public Publisher<HttpResponse> authorizationRedirect(HttpRequest originating) {
        return twitterClient.requestToken(routeUrlBuilder.buildCallbackUrl(originating, getName()).toString())
                .filter(map -> Boolean.valueOf(map.getOrDefault(PARAM_CALLBACK_CONF, "false")))
                .map(map -> {
                    String url = UriBuilder.of("https://api.twitter.com/oauth/authenticate")
                            .queryParam(PARAM_TOKEN, map.get(PARAM_TOKEN))
                            .build()
                            .toString();
                    return (HttpResponse) HttpResponse.status(HttpStatus.FOUND).header(HttpHeaders.LOCATION, url);
                }).defaultIfEmpty(HttpResponse.notFound())
                .toFlowable();
    }

    @Override
    public Publisher<AuthenticationResponse> onCallback(HttpRequest<Map<String, Object>> request) {
        HttpParameters parameters = request.getParameters();

        return twitterClient.accessToken(parameters.get(PARAM_TOKEN), parameters.get(PARAM_VERIFIER))
                .flatMap(map -> {
                    return twitterClient.userInfo(map.get(PARAM_TOKEN), map.get(PARAM_TOKEN_SECRET))
                            .map(userInfo -> {
                                return (AuthenticationResponse) new UserDetails(userInfo.get("screen_name").toString(), Collections.singletonList("ROLE_TWITTER"));
                            });
                })
                .toFlowable()
                .onErrorReturn(error -> new AuthenticationFailed());
    }

}
