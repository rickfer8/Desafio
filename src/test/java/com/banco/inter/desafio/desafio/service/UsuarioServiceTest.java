package com.banco.inter.desafio.desafio.service;

import static org.junit.Assert.assertNotNull;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.banco.inter.desafio.dao.UsuarioDAO;
import com.banco.inter.desafio.entidade.Usuario;
import com.banco.inter.desafio.exception.NegocioException;
import com.banco.inter.desafio.security.SecurityConfig;
import com.banco.inter.desafio.service.UsuarioService;

public class UsuarioServiceTest {
	
	@InjectMocks
	private UsuarioService usuarioService;
	
	@Mock
	private UsuarioDAO dao;
	
	@Mock
	private SecurityConfig security;
	
	private Usuario mockUsuario() {
		Usuario usuario = new Usuario();		
		usuario.setNome("Ricardo Ribeiro");
		usuario.setEmail("ricardo.ferib@gmail.com");
		return usuario;
	}
	
	private Usuario mockUsuarioSalvo() {
		Usuario usuario = new Usuario();		
		usuario.setId(1l);
		usuario.setNome("Nome Criptografado");
		usuario.setEmail("Email Criptografado");
		return usuario;
	}
	
	private KeyPair mockKeyPairVazio() {
		PublicKey chavePublica = null;
		PrivateKey chavePrivada = null;
		KeyPair keyPar = new KeyPair(chavePublica, chavePrivada);
		return keyPar;
	}
	
	private KeyPair mockKeyPair() throws NoSuchAlgorithmException {		
		return SecurityConfig.getParChave();
	}
	
	private Optional<Usuario>  mockUsuarioOptional() {
		Optional<Usuario> optional = Optional.of(mockUsuarioSalvo());
		return optional;
	}
	
	@Before
	public void setup() {
		MockitoAnnotations.initMocks(this);
	}
	
	@Test
	public void salvarTest() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		Usuario usuario = mockUsuario();

		Mockito.when( security.criptografar(Mockito.anyString())).thenReturn(Mockito.anyString());
		Mockito.when( dao.save(usuario)).thenReturn(mockUsuarioSalvo());
		assertNotNull(usuarioService.salvar(usuario));
	}
	
	@Test
	public void listarTodosTest() {		
		Mockito.when( dao.findAll()).thenReturn(Arrays.asList(mockUsuarioSalvo()));
		assertNotNull(usuarioService.listarTodos());
	}
	
	@Test
	public void atualizarTest() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		Usuario usuario = mockUsuarioSalvo();		
		usuarioService.getMapchave().put(1l,  mockKeyPair());
		Mockito.when( security.criptografar(Mockito.anyString())).thenReturn(Mockito.anyString());
		Mockito.when( dao.save(usuario)).thenReturn(mockUsuarioSalvo());
		assertNotNull(usuarioService.atualiza(usuario));
	}
	
	@Test(expected = NegocioException.class) 
	public void atualizarTestInvalidKeyException() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		Usuario usuario = mockUsuarioSalvo();
		usuarioService.getMapchave().put(1l, mockKeyPairVazio());
		Mockito.when( security.criptografar(Mockito.anyString())).thenThrow(new InvalidKeyException());		
		assertNotNull(usuarioService.atualiza(usuario));
	}
	
	@Test
	public void recuperarChavePorUsuarioTest() throws NoSuchAlgorithmException{
		usuarioService.getMapchave().put(1l, mockKeyPair());
		assertNotNull(usuarioService.recuperarChavePorUsuario(1l));
	}
	
	@Test
	public void removerUsuarioTest(){
		Usuario usuario = mockUsuarioSalvo();		
		usuarioService.removerUsuario(usuario);
	}
	
	@Test
	public void consultarUsuarioPorIdTest(){
		Mockito.when(dao.findById(1l)).thenReturn(mockUsuarioOptional());		
		assertNotNull(usuarioService.consultarUsuarioPorId(1l));
	}

}
