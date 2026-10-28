#ifndef DREAMYEMU_IOS_H
#define DREAMYEMU_IOS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* O que `dreamyemu_ios_passo` devolve. Os números são o contrato com o Swift. */
#define DREAMYEMU_SEM_SESSAO (-1)
#define DREAMYEMU_QUADRO 0
#define DREAMYEMU_RODANDO 1
#define DREAMYEMU_ADIANTADO 2
#define DREAMYEMU_PAROU 3

/* Ponteiro opaco. A Swift não olha para dentro. */
typedef struct DreamyemuIos DreamyemuIos;

/*
 * `documentos` é a pasta Documents do aplicativo: as ROMs ficam em `documentos/roms`,
 * que o app de Arquivos enxerga. `suporte` é Library/Application Support: cache, saves
 * e o aparelho virtual. Os dois são caminhos de arquivo, em UTF-8, terminados em zero.
 * Devolve nulo se um dos ponteiros for nulo.
 */
DreamyemuIos *dreamyemu_ios_cria(const char *documentos, const char *suporte);
void dreamyemu_ios_destroi(DreamyemuIos *app);

/* Quantos jogos a última varredura achou. Varre de novo a pasta de ROMs. */
int32_t dreamyemu_ios_varre(DreamyemuIos *app);

/* Título do jogo `indice`, válido até a próxima varredura. Nulo se o índice não existe. */
const char *dreamyemu_ios_titulo(DreamyemuIos *app, int32_t indice);

/*
 * Começa o jogo `indice`. 0 quando a sessão subiu; -1 quando não, e a razão fica em
 * `dreamyemu_ios_erro` até a próxima chamada que a substitua.
 */
int32_t dreamyemu_ios_comeca(DreamyemuIos *app, int32_t indice);
void dreamyemu_ios_para(DreamyemuIos *app);

/*
 * Uma volta do laço: entrega o controle, avança o jogo o tempo real que passou e publica
 * o quadro. A chamada é da linha de execução da interface; não é segura de outra linha.
 */
int32_t dreamyemu_ios_passo(DreamyemuIos *app);

/*
 * O quadro corrente, em BGRA8, com a origem no canto superior esquerdo. O ponteiro vale
 * até o próximo `dreamyemu_ios_passo` ou `dreamyemu_ios_para`. `largura` e `altura` podem ser nulos.
 * Devolve nulo quando não há quadro.
 */
const uint8_t *dreamyemu_ios_quadro(DreamyemuIos *app, uint32_t *largura, uint32_t *altura);

/* `indice` é a posição em `BUTTON_NAMES` do núcleo (`b1` é 0, `up` é 12). `apertado` é 0 ou 1. */
void dreamyemu_ios_botao(DreamyemuIos *app, uint32_t indice, int32_t apertado);

/* Eixo do manche, centrado em zero. `indice` 0 é X, 1 é Y. O curso é -128..=128. */
void dreamyemu_ios_eixo(DreamyemuIos *app, uint32_t indice, int32_t valor);

/* -1 quando o nome não é botão do Zeebo. */
int32_t dreamyemu_ios_botao_por_nome(const char *nome);

/* Texto da última falha, ou string vazia. Vale até a próxima chamada que o substitua. */
const char *dreamyemu_ios_erro(DreamyemuIos *app);

#ifdef __cplusplus
}
#endif

#endif
