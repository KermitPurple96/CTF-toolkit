<#
    Fixture para el test del ofuscador.

    Cubre las formas de declaracion que el regex original de findFUNCs no
    detectaba, y que ninguno de los tres scripts reales (powercat, nishang,
    ConPtyShell) usa. Es autonomo y no abre sockets, asi que el test puede
    ejecutarlo y comparar su salida antes y despues de ofuscar.

    Los textos que imprime no repiten ningun nombre de funcion a proposito: el
    renombrado tambien entra en los literales de cadena, de modo que un mensaje
    que mencionase su propia funcion cambiaria al ofuscar.
#>

# parentesis pegado al nombre
function Get-Payload($a, $b) {
    return "$a$b"
}

# calificador de ambito en la declaracion
function global:Invoke-Thing {
    param($Message)
    Write-Output "recibido: $Message"
}

# la llave abre en la linea siguiente
function Do-Work ($x)
{
    $result = Get-Payload $x "-listo"
    Invoke-Thing -Message $result
    return $result
}

# nombre corto, en el limite del minimo
function Wrap {
    # llamada con otra capitalizacion: powershell no distingue, sed si
    $out = do-work "inicio"
    Write-Output "resultado: $out"

    # variable con calificador y variable automatica en la misma linea
    $global:Marker = $PSBoundParameters.Count
    Write-Output "marca: $($global:Marker)"
}

Wrap
