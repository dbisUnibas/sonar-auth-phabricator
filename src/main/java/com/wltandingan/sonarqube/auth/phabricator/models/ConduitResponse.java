package com.wltandingan.sonarqube.auth.phabricator.models;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

/**
 * @author Willie Loyd Tandingan
 * @since 1.0.0
 */
public class ConduitResponse<T> {

    @SerializedName("result")
    private T result;

    public ConduitResponse() {
        // making sure there is always the default constructor
    }

    public T getResult() {
        return result;
    }

    public static <P> P parse(Class<P> clazz, String json) {
        final Gson gson = new Gson();
        return gson.fromJson(json, clazz);
    }

}
