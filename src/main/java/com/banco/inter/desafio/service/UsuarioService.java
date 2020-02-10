package com.banco.inter.desafio.service;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.banco.inter.desafio.constante.MensagemConstante;
import com.banco.inter.desafio.dao.UsuarioDAO;
import com.banco.inter.desafio.dto.UsuarioSaveDTO;
import com.banco.inter.desafio.entidade.Usuario;
import com.banco.inter.desafio.exception.NegocioException;
import com.banco.inter.desafio.exception.NotFoundException;
import com.banco.inter.desafio.security.SecurityConfig;

@Service
public class UsuarioService {
	
	@Autowired
	private UsuarioDAO dao;
		
	private SecurityConfig security;
	
	private static final Map<Long, KeyPair> mapChave = new HashMap<>();
	
	/**
	 * Método responsável por salvar um Usuario
	 *
	 * @param {@link Usuario}
	 * 
	 * @author ricardo.ferib@gmail.com
	 *
	 * @return {@link UsuarioSaveDTO} - DTO do Usuario
	 *
	 * @throws NoSuchAlgorithmException - Erro ao criar as chaves publicas e privada.
	 * @throws InvalidKeyException - Erro inesperado ao criptografar.
	 * @throws NoSuchPaddingException - Erro inesperado ao criptografar.
	 * @throws BadPaddingException - Erro inesperado ao criptografar.
	 * @throws IllegalBlockSizeException - Erro inesperado ao criptografar.	 
	 */
	
	public UsuarioSaveDTO salvar(Usuario u) {
		Usuario usuario = new Usuario();
		try {
			
			KeyPair parChave = SecurityConfig.getParChave();
			security = new SecurityConfig(parChave.getPublic(), parChave.getPrivate());			
			String nomeCriptografado = security.criptografar(u.getNome());
			String emailCriptografado = security.criptografar(u.getEmail());
			
			u.setNome(nomeCriptografado);
			u.setEmail(emailCriptografado);
			usuario = dao.save(u);
			mapChave.put(usuario.getId(), parChave);
		
		} catch (NoSuchAlgorithmException e) {			
			throw new NegocioException(MensagemConstante.ERRO_AO_GERAR_CHAVE + e);
		} catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {			
			throw new NegocioException(MensagemConstante.ERRO_NA_CRIPTOGRAFIA + e);
		}
		
		return UsuarioSaveDTO.mapper(usuario);	
	}
	
	/**
	 * Método responsável por listar todos os Usuarios cadastrados	
	 * 
	 * @author ricardo.ferib@gmail.com
	 *
	 * @return {@link List<UsuarioSaveDTO>} - Lista dos usuarios cadastrados
	 */
	
	public List<UsuarioSaveDTO> listarTodos(){
		List<Usuario> usuarios = dao.findAll();
		List<UsuarioSaveDTO> usuariosDTO = usuarios.stream().map(usuario -> UsuarioSaveDTO.mapper(usuario)).collect(Collectors.toList());
		
		return usuariosDTO;
	}
	
	/**
	 * Método responsável por atualizar um Usuario
	 *
	 * @param {@link Usuario}
	 * 
	 * @author ricardo.ferib@gmail.com
	 *
	 * @return {@link UsuarioSaveDTO} - DTO do Usuario
	 *
	 * @throws NoSuchAlgorithmException - Erro ao criar as chaves publicas e privada.
	 * @throws InvalidKeyException - Erro inesperado ao criptografar.
	 * @throws NoSuchPaddingException - Erro inesperado ao criptografar.
	 * @throws BadPaddingException - Erro inesperado ao criptografar.
	 * @throws IllegalBlockSizeException - Erro inesperado ao criptografar.	 
	 */
	
	public UsuarioSaveDTO atualiza(Usuario u) {
		Usuario usuario = new Usuario();
		KeyPair parChaves = recuperarChaves(u.getId());
		security = new SecurityConfig(parChaves.getPublic(), parChaves.getPrivate());		

		try {
			String nomeCriptografado = security.criptografar(u.getNome());
			String emailCriptografado = security.criptografar(u.getEmail());
			
			u.setNome(nomeCriptografado);
			u.setEmail(emailCriptografado);			
			usuario = dao.save(u);
			
		} catch (NoSuchAlgorithmException e) {			
			throw new NegocioException(MensagemConstante.ERRO_AO_GERAR_CHAVE + e);
		} catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {			
			throw new NegocioException(MensagemConstante.ERRO_NA_CRIPTOGRAFIA + e);
		}
		
		return UsuarioSaveDTO.mapper(usuario);		
	}
	
	/**
	 * Método responsável por recuperar a chave Privada e Publica
	 *
	 * @param {@link Long id} - Id do Usuario
	 * 
	 * @author ricardo.ferib@gmail.com
	 *
	 * @return {@link KeyPair} - Chaves privada e publica
	 */
	
	private KeyPair recuperarChaves(Long id) {
		KeyPair parChaves = null;
		Set<Long> chaves = mapChave.keySet();

		for (Iterator<Long> iterator = chaves.iterator(); iterator.hasNext();) {
			if(iterator.next().equals(id)) {				
				parChaves = mapChave.get(id);
				break;
			}			
		}
		return parChaves;
	}
	

	/**
	 * Método responsável por recuperar a chave Publica
	 *
	 * @param {@link Long id} - Id do Usuario
	 * 
	 * @author ricardo.ferib@gmail.com
	 *
	 * @return {@link String} - Chave publica
	 */
	
	public String recuperarChavePorUsuario(Long id) {		;
		KeyPair parChaves = recuperarChaves(id);
		String chave = Base64.getEncoder().encodeToString(parChaves.getPublic().getEncoded());				
		return chave;		
	}
	
	/**
	 * Método responsável por remover um Usuario
	 *
	 * @param {@link usuario} - Usuario
	 * 
	 * @author ricardo.ferib@gmail.com
	 *	 
	 */
	
	public void removerUsuario(Usuario usuario) {
		dao.delete(usuario);
	}
	
	/**
	 * Método responsável por consultar um Usuario e descriptografar os seus dados
	 *
	 * @param {@link Long id} - Id do Usuario
	 * @param {@link chavePublica} - Chave publica 
	 * 
	 * @author ricardo.ferib@gmail.com
	 * 
	 * @return {@link UsuarioSaveDTO} - Retorno do Usuario Cadastrado
	 *	 
	 */
	
	public UsuarioSaveDTO consultarUsuarioPorId(Long id, String chavePublica) {
		Optional<Usuario> resultado = dao.findById(id);

		if (!resultado.isPresent()) {
			throw new NotFoundException(MensagemConstante.USUARIO_NAO_ENCONTRADO + id);
		}

		Usuario usuario = resultado.get();
		KeyPair parChaves = recuperarChaves(usuario.getId());		

		security = new SecurityConfig(parChaves.getPublic(), parChaves.getPrivate());

		try {
			String emailDescriptografado = security.descriptografar(usuario.getEmail());
			String nomeDescriptografado = security.descriptografar(usuario.getNome());
			usuario.setNome(nomeDescriptografado);
			usuario.setEmail(emailDescriptografado);
		} catch (InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
			throw new NegocioException(MensagemConstante.ERRO_NA_CRIPTOGRAFIA + e);
		} catch (NoSuchAlgorithmException e) {
			throw new NegocioException(MensagemConstante.ERRO_AO_GERAR_CHAVE + e);
		} catch (IOException e) {
			throw new NegocioException(MensagemConstante.ERRO_NA_CRIPTOGRAFIA + e);
		}

		return UsuarioSaveDTO.mapper(resultado.get());
	}
	
	/**
	 * Método responsável por consultar um Usuario
	 *
	 * @param {@link Long id} - Id do Usuario
	 * 
	 * @author ricardo.ferib@gmail.com	 
	 * 
	 * @return {@link UsuarioSaveDTO} - Retorno do Usuario Cadastrado
	 *	 
	 */
	
	public UsuarioSaveDTO consultarUsuarioPorId(Long id) {
		Optional<Usuario> resultado = dao.findById(id);

		if (!resultado.isPresent()) {
			throw new NotFoundException(MensagemConstante.USUARIO_NAO_ENCONTRADO + id);
		}
		
		return UsuarioSaveDTO.mapper(resultado.get());
	}

	public static Map<Long, KeyPair> getMapchave() {
		return mapChave;
	}

}
