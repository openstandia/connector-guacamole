package jp.openstandia.connector.guacamole;

import org.identityconnectors.framework.common.objects.*;

import java.util.Set;

public interface GuacamoleObjectHandler {

    Uid create(Set<Attribute> attributes);

    Set<AttributeDelta> updateDelta(Uid uid, Set<AttributeDelta> modifications, OperationOptions options);

    void delete(Uid uid, OperationOptions options);

    void query(GuacamoleFilter filter, ResultsHandler resultsHandler, OperationOptions options);


}
