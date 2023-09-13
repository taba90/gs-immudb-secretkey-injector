package org.geoserver.immudb;

import org.geoserver.catalog.CatalogInfo;
import org.geoserver.catalog.ResourceInfo;
import org.geoserver.ows.Dispatcher;
import org.geoserver.ows.Request;
import org.geoserver.security.DataAccessLimits;
import org.geoserver.security.ResourceAccessManager;
import org.geoserver.security.ResourceAccessManagerWrapper;
import org.geoserver.security.VectorAccessLimits;
import org.geotools.util.Base64;
import org.opengis.filter.Filter;
import org.springframework.security.core.Authentication;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

public class SecretAndIVInjectorAccessManager extends ResourceAccessManagerWrapper {

    private static final String X_KEY_IV="X-KEY-IV";

    public SecretAndIVInjectorAccessManager(ResourceAccessManager delegate){
        this.delegate=delegate;
    }
    @Nullable
    @Override
    public Filter getSecurityFilter(Authentication authentication, Class<? extends CatalogInfo> aClass) {
        return null;
    }

    @Override
    public DataAccessLimits getAccessLimits(Authentication user, ResourceInfo resource) {
        DataAccessLimits dataAccessLimits= super.getAccessLimits(user, resource);
        if (dataAccessLimits instanceof VectorAccessLimits) {
            VectorAccessLimits vectorAccessLimits = (VectorAccessLimits) dataAccessLimits;
            Request request = Dispatcher.REQUEST.get();
            HttpServletRequest httpServletRequest = request.getHttpRequest();
            String header = httpServletRequest.getHeader(X_KEY_IV);
            if (header != null && !header.isEmpty()) {
                String decoded = new String(Base64.decode(header));
                String[] splitted = decoded.split("\\$");
                if (splitted.length == 2) {
                    dataAccessLimits=new SecretAndIVAccessLimits(splitted[1],splitted[0],vectorAccessLimits);
                }
            }
        }
        return dataAccessLimits;
    }
}
