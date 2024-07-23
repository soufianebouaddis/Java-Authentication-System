package com.auth_system.authentication.system.auth.mapper;

public interface Mapper <Source, Destination> {
    Source DtoToEntity(Destination destination);

    Destination EntityToDto(Source source);
}
