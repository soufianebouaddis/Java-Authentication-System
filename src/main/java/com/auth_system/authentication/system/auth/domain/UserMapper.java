package com.auth_system.authentication.system.auth.domain;

import com.auth_system.authentication.system.auth.dto.UserDto;
import com.auth_system.authentication.system.auth.mapper.Mapper;
import com.auth_system.authentication.system.auth.service.IUserAuth;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
class UserMapper implements Mapper<IUserAuth, UserDto> {
    private final ModelMapper modelMapper;

    public UserMapper(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }
    @Override
    public IUserAuth DtoToEntity(UserDto destination) {
        return this.modelMapper.map(destination, IUserAuth.class);
    }
    @Override
    public UserDto EntityToDto(IUserAuth source) {
        return this.modelMapper.map(source, UserDto.class);
    }

}
