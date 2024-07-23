package com.auth_system.authentication.system.auth.domain;

import com.auth_system.authentication.system.auth.dto.RefreshTokenDTO;
import com.auth_system.authentication.system.auth.mapper.Mapper;
import com.auth_system.authentication.system.util.IRefreshToken;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component("RefreshTokenMapper")
class RefreshTokenMapper implements Mapper<IRefreshToken, RefreshTokenDTO> {
    private final ModelMapper modelMapper;

    public RefreshTokenMapper(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }
    @Override
    public IRefreshToken DtoToEntity(RefreshTokenDTO destination) {
        return this.modelMapper.map(destination, IRefreshToken.class);
    }

    @Override
    public RefreshTokenDTO EntityToDto(IRefreshToken source) {
        return this.modelMapper.map(source, RefreshTokenDTO.class);
    }
}