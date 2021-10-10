package br.com.zapia.wpp.api.ws.model.communication;

import java.time.LocalDateTime;

public class MediaConnResponse {

    private MediaConn media_conn;

    public MediaConn getMedia_conn() {
        return media_conn;
    }

    public class MediaConn {
        private String auth;
        private long ttl;
        private Host[] hosts;
        private transient LocalDateTime fetchDate;

        public String getAuth() {
            return auth;
        }

        public long getTtl() {
            return ttl;
        }

        public Host[] getHosts() {
            return hosts;
        }

        public LocalDateTime getFetchDate() {
            return fetchDate;
        }

        public void setFetchDate(LocalDateTime fetchDate) {
            this.fetchDate = fetchDate;
        }

        public class Host {
            private String hostname;

            public String getHostname() {
                return hostname;
            }
        }
    }

}
