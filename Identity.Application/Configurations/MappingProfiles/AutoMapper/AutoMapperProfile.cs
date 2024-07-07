using AutoMapper;
using Identity.Application.Dtos;
using Identity.Application.Dtos.Users;
using Identity.Domain.Entities;

namespace Identity.Application.Configurations.MappingProfiles.AutoMapper
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            CreateMap<UserDto, User>().ReverseMap();
            CreateMap<Menu, MenuDto>().ReverseMap();
        }
    }
}