package test.github.oauth;

import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.client.annotation.Client;
import io.reactivex.Flowable;

@Header(name = "User-Agent", value = "Micronaut")
@Client("https://api.github.com")
public interface GithubApiClient {

    @Get("/user")
    Flowable<GithubUser> getUser(@Header("Authorization") String authorization);
}
