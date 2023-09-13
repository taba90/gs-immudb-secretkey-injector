package org.geoserver.immudb;

import org.geoserver.ows.Dispatcher;
import org.geoserver.ows.Request;
import org.geoserver.security.VectorAccessLimits;
import org.geotools.data.Query;
import org.geotools.util.Base64;
import org.geotools.util.factory.Hints;
import org.locationtech.jts.geom.MultiPolygon;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;


public class SecretAndIVAccessLimits extends VectorAccessLimits {


    private String key;
    private String iv;

    public static final Hints.OptionKey SECRET_KEY=new Hints.OptionKey("secretKey");

    public static final Hints.OptionKey IV=new Hints.OptionKey("IV");

    public SecretAndIVAccessLimits(String key, String iv,VectorAccessLimits limits) {
        super(limits.getMode(), limits.getReadAttributes(), limits.getReadFilter(), limits.getWriteAttributes(), limits.getWriteFilter(), limits.getClipVectorFilter() instanceof MultiPolygon?((MultiPolygon) limits.getClipVectorFilter()):null);
        this.key=key;
        this.iv=iv;
    }

    @Override
    public Query getReadQuery() {
        Query query= super.getReadQuery();
        query.getHints().put(SECRET_KEY,key);
        query.getHints().put(IV,iv);
        return query;
    }
}
